package postgres

import (
	"fmt"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	ds "goldfiglabs.com/sgcheckup/internal/dockersession"
	"k8s.io/apimachinery/pkg/util/wait"
)

type DBCredential struct {
	Username string
	Password string
}

type PostgresService interface {
	ShutDown() error
	ConnectionString(cred *DBCredential) string
	SuperUserCredential() DBCredential
	Address() nat.PortBinding
}

type DockerPostgresService struct {
	ds.ContainerService
	superUserCredential *DBCredential
	address             nat.PortBinding
}

type DockerPostgresOptions struct {
	Ref                 string
	Port                int
	ReuseExisting       bool
	SuperUserCredential *DBCredential
}

var _ PostgresService = &DockerPostgresService{}

func (dps *DockerPostgresService) ConnectionString(cred *DBCredential) string {
	return fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		dps.address.HostIP, dps.address.HostPort, cred.Username, cred.Password, "introspector")
}

func (dps *DockerPostgresService) SuperUserCredential() DBCredential {
	return *dps.superUserCredential
}

func (dps *DockerPostgresService) Address() nat.PortBinding {
	return dps.address
}

const postgresContainerName = "sgCheckup-db"
const defaultPostgresRef = "supabase/postgres:0.13.0"
const defaultPostgresPort = 5432

func (o *DockerPostgresOptions) fillInDefaults() {
	if o.Ref == "" {
		o.Ref = defaultPostgresRef
	}
	if o.Port == 0 {
		o.Port = defaultPostgresPort
	}
	if o.SuperUserCredential == nil {
		o.SuperUserCredential = &DBCredential{
			Username: "postgres",
			Password: "postgres",
		}
	}
}

func NewDockerPostgresService(s *ds.Session, opts DockerPostgresOptions) (*DockerPostgresService, error) {
	log.Info("Running postgres")
	opts.fillInDefaults()
	err := s.RequireImage(opts.Ref)
	if err != nil {
		return nil, err
	}

	service, err := createPostgresContainer(s, &opts)
	if err != nil {
		return nil, err
	}
	err = s.Client.ContainerStart(s.Ctx, service.ContainerID, types.ContainerStartOptions{})
	if err != nil {
		return nil, err
	}
	err = wait.PollImmediate(2*time.Second, 60*time.Second, func() (bool, error) {
		resp, err := s.Client.ContainerInspect(s.Ctx, service.ContainerID)
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

func createPostgresContainer(
	s *ds.Session,
	opts *DockerPostgresOptions,
) (*DockerPostgresService, error) {
	postgresNatPort, err := nat.NewPort("tcp", strconv.Itoa(opts.Port))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create postgres nat.Port")
	}
	existingContainer, err := s.FindContainer(postgresContainerName)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list existing containers")
	}
	if existingContainer != nil {
		if opts.ReuseExisting {
			containerDesc, err := s.Client.ContainerInspect(s.Ctx, existingContainer.ID)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to inspect running postgres")
			}
			bindings := containerDesc.HostConfig.PortBindings[postgresNatPort]
			// TODO: pull out credential?
			return &DockerPostgresService{
				ContainerService: ds.ContainerService{
					ContainerID:   existingContainer.ID,
					DockerSession: s,
				},
				superUserCredential: opts.SuperUserCredential,
				address:             bindings[0],
			}, nil
		}
		err = s.StopAndRemoveContainer(existingContainer.ID)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to remove existing container")
		}
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
		fmt.Sprintf("POSTGRES_USER=%v", opts.SuperUserCredential.Username),
		fmt.Sprintf("POSTGRES_PASSWORD=%v", opts.SuperUserCredential.Password),
	}
	containerBody, err := s.Client.ContainerCreate(s.Ctx, &container.Config{
		Image:        opts.Ref,
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
	return &DockerPostgresService{
		ContainerService: ds.ContainerService{
			ContainerID:   containerBody.ID,
			DockerSession: s,
		},
		superUserCredential: opts.SuperUserCredential,
		address:             hostAddress,
	}, nil
}