package docker

import (
	"context"
	"github.com/CriticalSecurity/cc-scanner/internal/errors"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func RemoveContainers(idArray []string) {
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		errors.HandleError(err, "RemoveContainers NewEnvClient Error")
	}
	for _, id := range idArray {
		if err := cli.ContainerRemove(ctx, id, types.ContainerRemoveOptions{}); err != nil {
			errors.HandleError(err, "RemoveContainers ContainerRemove Error")
		}
	}
}

func StartContainer(
	imageName *string,
	containerName *string,
	config *container.Config,
	hostConfig *container.HostConfig) (*container.ContainerCreateCreatedBody, error){
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		return nil, NewEnvClientErr
	}
	_, ImagePullErr := cli.ImagePull(ctx, *imageName, types.ImagePullOptions{})
	if ImagePullErr != nil {
		return nil, ImagePullErr
	}
	ContainerList, ContainerListErr := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if ContainerListErr != nil {
		return nil, ContainerListErr
	}
	for _, c := range ContainerList {
		if c.Names[0] == "/" + *containerName && c.State == "running" {
			return nil, nil
		}
		if c.Names[0] == "/" + *containerName && c.State == "exited" {
			if err := cli.ContainerStart(ctx, c.ID, types.ContainerStartOptions{}); err != nil {
				return nil, err
			}
			return nil, nil
		}
	}
	Container, err := cli.ContainerCreate(
		ctx,
		config,
		hostConfig,
		nil,
		*containerName,
	)
	if err != nil {
		return nil, err
	}
	if err := cli.ContainerStart(ctx, Container.ID, types.ContainerStartOptions{}); err != nil {
		return nil, err
	}
	return &Container, nil
}