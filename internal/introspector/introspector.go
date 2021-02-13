package introspector

import (
	"bufio"
	"fmt"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	ds "goldfiglabs.com/sgcheckup/internal/dockersession"
	ps "goldfiglabs.com/sgcheckup/internal/postgres"
)

const introspectorRef = "goldfig/introspector:latest"
const introspectorContainerName = "sgCheckup-introspector"

// Service is a wrapper around a docker container running
// https://github.com/goldfiglabs/introspector.
type Service struct {
	ds.ContainerService
}

func New(s *ds.Session, postgresService ps.PostgresService) (*Service, error) {
	log.Info("Checking for introspector image")
	err := s.RequireImage(introspectorRef)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get instrospector docker image")
	}
	service, err := createIntrospectorContainer(s, postgresService)
	if err != nil {
		return nil, err
	}
	err = s.Client.ContainerStart(s.Ctx, service.ContainerID, types.ContainerStartOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to start introspector")
	}
	err = service.runCommand([]string{"init"}, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to init introspector")
	}
	return service, nil
}

func (i *Service) ImportAWSService(environmentCredentials []string, serviceSpec string) error {
	return i.runCommand(
		[]string{"account", "aws", "import", "--force", "--service", serviceSpec}, environmentCredentials)
}

func createIntrospectorContainer(s *ds.Session, postgresService ps.PostgresService) (*Service, error) {
	existingContainer, err := s.FindContainer(introspectorContainerName)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list existing containers")
	}
	if existingContainer != nil {
		err = s.StopAndRemoveContainer(existingContainer.ID)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to remove existing container")
		}
	}

	credential := postgresService.SuperUserCredential()
	address := postgresService.Address()
	envVars := []string{
		fmt.Sprintf("INTROSPECTOR_SU_DB_USER=%v", credential.Username),
		fmt.Sprintf("INTROSPECTOR_SU_DB_PASSWORD=%v", credential.Password),
		fmt.Sprintf("INTROSPECTOR_DB_HOST=%v", address.HostIP),
		fmt.Sprintf("INTROSPECTOR_DB_PORT=%v", address.HostPort),
	}
	log.Infof("Using environment %v", envVars)
	containerBody, err := s.Client.ContainerCreate(s.Ctx, &container.Config{
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
	return &Service{
		ds.ContainerService{ContainerID: containerBody.ID, DockerSession: s},
	}, nil
}

func (i *Service) runCommand(args []string, env []string) error {
	envVars := []string{}
	if env != nil {
		envVars = append(envVars, env...)
	}
	cmdPrefix := []string{"python", "introspector.py"}
	cmd := append(cmdPrefix, args...)
	execResp, err := i.DockerSession.Client.ContainerExecCreate(i.DockerSession.Ctx, i.ContainerID, types.ExecConfig{
		Cmd:          cmd,
		AttachStderr: true,
		AttachStdout: true,
		AttachStdin:  true,
		Env:          envVars,
	})
	if err != nil {
		return errors.Wrap(err, "Failed to create exec")
	}
	resp, err := i.DockerSession.Client.ContainerExecAttach(i.DockerSession.Ctx, execResp.ID, types.ExecStartCheck{})
	if err != nil {
		return errors.Wrap(err, "Failed to attach to exec")
	}
	defer resp.Close()
	// TODO: correct logging here

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

	case <-i.DockerSession.Ctx.Done():
		return i.DockerSession.Ctx.Err()
	}

	return nil
}