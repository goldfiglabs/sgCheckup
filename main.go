package main

import (
	"context"
	"flag"
	"io"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	log "github.com/sirupsen/logrus"

	"github.com/phayes/freeport"
)

type dbCredential struct {
	username string
	password string
}

type dbInfo struct {
	superuser *dbCredential
	importer  *dbCredential
	reader    *dbCredential
	// hostname string
	// port int
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

type dbContainerInfo struct {
	ID      string
	address nat.PortBinding
}

func createPostgresContainer(ctx context.Context, dbInfo *dbInfo, dockerClient *client.Client) (*dbContainerInfo, error) {
	existingContainers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(filters.Arg("name", "/"+postgresContainerName)),
		All:     true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list existing containers")
	}
	if len(existingContainers) == 1 {
		container := existingContainers[0]
		err = dockerClient.ContainerRemove(ctx, container.ID, types.ContainerRemoveOptions{
			RemoveVolumes: false,
		})
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

	envVars := []string{"POSTGRES_DB=postgres", "POSTGRES_USER=postgres", "POSTGRES_PASSWORD=postgres"}
	volumes := map[string]struct{}{"pg_data:/var/lib/postgresql/data": {}}
	containerBody, err := dockerClient.ContainerCreate(ctx, &container.Config{
		Image:        postgresRef,
		ExposedPorts: exposedPorts,
		Labels:       labels,
		Volumes:      volumes,
		Env:          envVars,
	}, &container.HostConfig{
		PortBindings: portBindings,
	}, &network.NetworkingConfig{}, nil, "sgCheckup-db")

	if err != nil {
		return nil, errors.Wrap(err, "Failed to create container")
	}
	log.Infof("container id %v", containerBody.ID)
	return &dbContainerInfo{
		ID:      containerBody.ID,
		address: hostAddress,
	}, nil
}

func runPostgres(ctx context.Context, dbInfo *dbInfo, dockerClient *client.Client) (*dbContainerInfo, error) {
	err := requireDockerImage(ctx, dockerClient, postgresRef)
	if err != nil {
		return nil, err
	}

	container, err := createPostgresContainer(ctx, dbInfo, dockerClient)
	if err != nil {
		return nil, err
	}
	err = dockerClient.ContainerStart(ctx, container.ID, types.ContainerStartOptions{})
	if err != nil {
		return nil, err
	}
	return container, nil
}

func stopPostgres(ctx context.Context, dockerClient *client.Client, container *dbContainerInfo) {
	dockerClient.ContainerRemove(ctx, container.ID, types.ContainerRemoveOptions{
		RemoveVolumes: false,
	})
}

func runIntrospector(dbInfo *dbInfo) error {
	ctx := context.Background()
	log.Info("Running introspector")
	dockerClient, err := getDockerClient()
	if err != nil {
		return errors.Wrap(err, "Failed to get docker client. Is it installed?")
	}
	postgresContainer, err := runPostgres(ctx, dbInfo, dockerClient)
	if err != nil {
		return errors.Wrap(err, "Failed to start postgres container")
	}

	return nil
}

func runSecurityGroupTool() {

}

func main() {
	var skipIntrospector bool
	flag.BoolVar(&skipIntrospector, "skip-introspector", false, "Skip running an import, use existing data")

	if !skipIntrospector {
		runIntrospector(&dbInfo{
			superuser: &dbCredential{
				username: "postgres",
				password: "postgres",
			},
			importer: &dbCredential{
				username: "introspector",
				password: "introspector",
			},
			reader: &dbCredential{
				username: "introspector_scoped",
				password: "introspector_scoped",
			},
		})
	}
}
