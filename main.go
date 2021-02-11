package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	log "github.com/sirupsen/logrus"

	"github.com/phayes/freeport"

	_ "github.com/lib/pq"
)

type dbCredential struct {
	username string
	password string
}

type dbInfo struct {
	superuser *dbCredential
	importer  *dbCredential
	// hostname string
	// port int
}

type containerService struct {
	ContainerID string
}

type dbService struct {
	containerService
	SuperUserCredential *dbCredential
	Address             nat.PortBinding
}

func (ds *dbService) ConnectionString(cred *dbCredential) string {
	return fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		ds.Address.HostIP, ds.Address.HostPort, cred.username, cred.password, "introspector")
}

type introspectorService struct {
	containerService
}

func (is *introspectorService) runCommand(ctx context.Context, dockerClient *client.Client, args []string, env []string) error {
	envVars := []string{}
	if env != nil {
		envVars = append(envVars, env...)
	}
	cmdPrefix := []string{"python", "introspector.py"}
	cmd := append(cmdPrefix, args...)
	execResp, err := dockerClient.ContainerExecCreate(ctx, is.ContainerID, types.ExecConfig{
		Cmd:          cmd,
		AttachStderr: true,
		AttachStdout: true,
		AttachStdin:  true,
		Env:          envVars,
	})
	if err != nil {
		return errors.Wrap(err, "Failed to create exec")
	}
	resp, err := dockerClient.ContainerExecAttach(ctx, execResp.ID, types.ExecStartCheck{})
	if err != nil {
		return errors.Wrap(err, "Failed to attach to exec")
	}
	defer resp.Close()

	// read the output
	outputDone := make(chan error)
	go func() {
		// StdCopy demultiplexes the stream into two buffers
		_, err = stdcopy.StdCopy(os.Stdout, os.Stderr, resp.Reader)
		outputDone <- err
	}()

	stdin := bufio.NewScanner(os.Stdin)
	go func() {
		for stdin.Scan() {
			resp.Conn.Write(stdin.Bytes())
			resp.Conn.Write([]byte("\n"))
		}
	}()

	select {
	case err := <-outputDone:
		if err != nil {
			return err
		}
		break

	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (cs *containerService) ShutDown(ctx context.Context, dockerClient *client.Client) error {
	return stopAndRemoveContainer(ctx, dockerClient, cs.ContainerID)
}

func getDockerClient() (*client.Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return cli, nil
}

const postgresRef = "supabase/postgres:0.13.0"
const postgresPort = 5432
const introspectorRef = "goldfig/lighthouse:latest"

func requireDockerImage(ctx context.Context, client *client.Client, ref string) error {
	images, err := client.ImageList(ctx, types.ImageListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", ref)),
	})
	if err != nil {
		return errors.WithMessage(err, "Failed to list images")
	}
	if len(images) == 0 {
		log.Infof("Image %v not found, pulling", ref)
		closer, err := client.ImagePull(ctx, ref, types.ImagePullOptions{})
		if err != nil {
			return errors.WithMessage(err, "Failed to pull image")
		}
		buf := new(strings.Builder)
		_, err = io.Copy(buf, closer)
		if err != nil {
			return err
		}
		log.Debug(buf.String())
		closer.Close()
	}
	return nil
}

const postgresContainerName = "sgCheckup-db"
const introspectorContainerName = "sgCheckup-introspector"

func createPostgresContainer(ctx context.Context, suCredential *dbCredential, dockerClient *client.Client) (*dbService, error) {
	existingContainers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(filters.Arg("name", "/"+postgresContainerName)),
		All:     true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list existing containers")
	}
	if len(existingContainers) == 1 {
		container := existingContainers[0]
		err = stopAndRemoveContainer(ctx, dockerClient, container.ID)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to remove existing container")
		}
	}

	postgresNatPort, err := nat.NewPort("tcp", strconv.Itoa(postgresPort))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create postgres nat.Port")
	}
	exposedPorts := make(nat.PortSet)
	exposedPorts[postgresNatPort] = struct{}{}

	hostPortRaw, err := freeport.GetFreePort()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to allocate host port")
	}
	hostAddress := nat.PortBinding{
		HostIP:   "127.0.0.1",
		HostPort: strconv.Itoa(hostPortRaw),
	}
	portBindings := make(nat.PortMap)
	portBindings[postgresNatPort] = []nat.PortBinding{hostAddress}

	labels := map[string]string{"sgCheckup": "db"}

	envVars := []string{"POSTGRES_DB=postgres",
		fmt.Sprintf("POSTGRES_USER=%v", suCredential.username),
		fmt.Sprintf("POSTGRES_PASSWORD=%v", suCredential.password),
	}
	containerBody, err := dockerClient.ContainerCreate(ctx, &container.Config{
		Image:        postgresRef,
		ExposedPorts: exposedPorts,
		Labels:       labels,
		Env:          envVars,
		Healthcheck: &container.HealthConfig{
			Test:    []string{"CMD", "pg_isready"},
			Timeout: 5 * time.Second,
			Retries: 3,
		},
	}, &container.HostConfig{
		PortBindings: portBindings,
		Mounts: []mount.Mount{
			{
				Type:   "volume",
				Source: "sg_checkup_pg_data",
				Target: "/var/lib/postgresql/data",
			},
		},
	}, &network.NetworkingConfig{}, nil, postgresContainerName)

	if err != nil {
		return nil, errors.Wrap(err, "Failed to create container")
	}
	log.Infof("postgres container id %v", containerBody.ID)
	return &dbService{
		containerService:    containerService{ContainerID: containerBody.ID},
		SuperUserCredential: suCredential,
		Address:             hostAddress,
	}, nil
}

func runPostgres(ctx context.Context, dockerClient *client.Client, suCredential *dbCredential) (*dbService, error) {
	log.Info("Running postgres")
	err := requireDockerImage(ctx, dockerClient, postgresRef)
	if err != nil {
		return nil, err
	}

	service, err := createPostgresContainer(ctx, suCredential, dockerClient)
	if err != nil {
		return nil, err
	}
	err = dockerClient.ContainerStart(ctx, service.ContainerID, types.ContainerStartOptions{})
	if err != nil {
		return nil, err
	}
	err = wait.PollImmediate(2*time.Second, 60*time.Second, func() (bool, error) {
		resp, err := dockerClient.ContainerInspect(ctx, service.ContainerID)
		if err != nil {
			return false, err
		}
		log.Infof("health: %v", resp.State.Health.Status)
		return resp.State.Health.Status == "healthy", nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "Postgres did not become healthy before timeout")
	}
	return service, nil
}

func stopAndRemoveContainer(ctx context.Context, dockerClient *client.Client, containerID string) error {
	err := dockerClient.ContainerStop(ctx, containerID, nil)
	if err != nil {
		errors.WithMessage(err, "Failed to stop container")
	}
	err = dockerClient.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{
		RemoveVolumes: false,
	})
	if err != nil {
		return errors.WithMessage(err, "Failed to remove container")
	}
	return nil
}

func createIntrospectorContainer(ctx context.Context, dockerClient *client.Client, postgresService *dbService) (*introspectorService, error) {
	existingContainers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(filters.Arg("name", "/"+introspectorContainerName)),
		All:     true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list existing containers")
	}
	if len(existingContainers) == 1 {
		container := existingContainers[0]
		err = stopAndRemoveContainer(ctx, dockerClient, container.ID)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to remove existing container")
		}
	}

	envVars := []string{
		fmt.Sprintf("INTROSPECTOR_SU_DB_USER=%v", postgresService.SuperUserCredential.username),
		fmt.Sprintf("INTROSPECTOR_SU_DB_PASSWORD=%v", postgresService.SuperUserCredential.password),
		fmt.Sprintf("INTROSPECTOR_DB_HOST=%v", postgresService.Address.HostIP),
		fmt.Sprintf("INTROSPECTOR_DB_PORT=%v", postgresService.Address.HostPort),
	}
	log.Infof("Using environment %v", envVars)
	containerBody, err := dockerClient.ContainerCreate(ctx, &container.Config{
		Image:  introspectorRef,
		Labels: map[string]string{"sgCheckup": "introspector"},
		Env:    envVars,
	}, &container.HostConfig{
		NetworkMode: "host",
	}, &network.NetworkingConfig{}, nil, introspectorContainerName)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create container")
	}
	log.Infof("introspector container ID %v", containerBody.ID)
	return &introspectorService{
		containerService{containerBody.ID},
	}, nil
}

func runIntrospector(ctx context.Context, dockerClient *client.Client, postgresService *dbService) (*introspectorService, error) {
	log.Info("Checking for introspector image")
	err := requireDockerImage(ctx, dockerClient, "lighthouse:latest")
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get instrospector docker image")
	}
	service, err := createIntrospectorContainer(ctx, dockerClient, postgresService)
	if err != nil {
		return nil, err
	}
	err = dockerClient.ContainerStart(ctx, service.ContainerID, types.ContainerStartOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to start introspector")
	}
	return service, nil
}

func loadAwsCredentials(ctx context.Context) ([]string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	env := []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%v", creds.AccessKeyID),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%v", creds.SecretAccessKey),
	}
	if len(creds.SessionToken) > 0 {
		env = append(env, fmt.Sprintf("AWS_SESSION_TOKEN=%v", creds.SessionToken))
	}
	return env, nil
}

func installDbFunction(db *sql.DB) error {
	const isRFC1918 = `CREATE OR REPLACE FUNCTION is_rfc1918block(block cidr)
	RETURNS boolean
	LANGUAGE plpgsql
	AS
	$$
	BEGIN
		RETURN
			('192.168.0.0/16' >>= block)
			OR ('172.16.0.0/12' >>= block)
			OR ('10.0.0.0/8' >>= block);
	END;
	$$`

	result, err := db.Exec(isRFC1918)
	if err != nil {
		return err
	}
	log.Infof("result %v", result)
	return nil
}

func runSecurityGroupTool(pgInfo string) (interface{}, error) {
	db, err := sql.Open("postgres", pgInfo)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to connect to db")
	}
	err = db.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to ping db")
	}
	log.Info("db ready")
	err = installDbFunction(db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to install fixture functions")
	}
	return nil, nil
}

func main() {
	var skipIntrospector bool
	flag.BoolVar(&skipIntrospector, "skip-introspector", false, "Skip running an import, use existing data")
	flag.Parse()

	ctx := context.Background()
	dockerClient, err := getDockerClient()
	if err != nil {
		panic(errors.Wrap(err, "Failed to get docker client. Is it installed?"))
	}
	importer := &dbCredential{
		username: "introspector",
		password: "introspector",
	}
	superuser := &dbCredential{
		username: "postgres",
		password: "postgres",
	}
	postgresService, err := runPostgres(ctx, dockerClient, superuser)
	if err != nil {
		panic(err)
	}
	if !skipIntrospector {
		introspectorService, err := runIntrospector(ctx, dockerClient, postgresService)
		if err != nil {
			panic(err)
		}
		err = introspectorService.runCommand(ctx, dockerClient, []string{"init"}, nil)
		if err != nil {
			panic(err)
		}
		awsCreds, err := loadAwsCredentials(ctx)
		if err != nil {
			panic(err)
		}
		err = introspectorService.runCommand(ctx,
			dockerClient, []string{"account", "aws", "import", "--force", "--service", "ec2=SecurityGroups,NetworkInterfaces"}, awsCreds)
		if err != nil {
			panic(err)
		}
		err = introspectorService.ShutDown(ctx, dockerClient)
		if err != nil {
			panic(err)
		}
	}
	_, err = runSecurityGroupTool(postgresService.ConnectionString(importer))
	if err != nil {
		panic(err)
	}
	/*err = postgresService.ShutDown(ctx, dockerClient)
	if err != nil {
		panic(err)
	}*/
}
