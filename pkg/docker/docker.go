package docker

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"io"
	"io/ioutil"
	"log"
)

func RemoveContainers(idArray []string) {
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("docker remove-containers error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
	}
	for _, id := range idArray {
		if ContainerRemovErr := cli.ContainerRemove(ctx, id, types.ContainerRemoveOptions{}); ContainerRemovErr != nil {
			err := fmt.Errorf("docker remove-containers error %v", ContainerRemovErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
		}
	}
	cli.Close()
}

func GetImages() {
	images := []string{NmapDockerImage, DnsReconImage, GVMImage, MongoDbDockerImage, OwaspZapImage, SastImage}
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("docker image-pull error %v", NewEnvClientErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
	}
	options := &types.ImagePullOptions{}
	for _, image := range images {
		out, ImagePullErr := cli.ImagePull(ctx, image, *options)
		if ImagePullErr != nil {
			err := fmt.Errorf("docker image-pull error %v", ImagePullErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		io.Copy(ioutil.Discard, out)
		out.Close()
	}
	pruneFilter := filters.NewArgs()
	pruneFilter.Add("dangling", "true")
	_, ImagesPruneErr := cli.ImagesPrune(ctx, pruneFilter)
	if ImagesPruneErr != nil {
		err := fmt.Errorf("docker images-prune error %v", ImagesPruneErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
	}
	cli.Close()
}

func StartContainer(
	imageName *string,
	containerName *string,
	config *container.Config,
	hostConfig *container.HostConfig) (*container.ContainerCreateCreatedBody, error) {
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		return nil, NewEnvClientErr
	}
	config.Image = *imageName
	ContainerList, ContainerListErr := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if ContainerListErr != nil {
		cli.Close()
		return nil, ContainerListErr
	}
	for _, c := range ContainerList {
		if c.Names[0] == "/"+*containerName && c.State == "running" {
			return nil, nil
		}
		if c.Names[0] == "/"+*containerName && c.State == "exited" {
			if err := cli.ContainerStart(ctx, c.ID, types.ContainerStartOptions{}); err != nil {
				cli.Close()
				return nil, err
			}
			cli.Close()
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
		cli.Close()
		return nil, err
	}
	if err := cli.ContainerStart(ctx, Container.ID, types.ContainerStartOptions{}); err != nil {
		cli.Close()
		return nil, err
	}
	cli.Close()
	return &Container, nil
}
