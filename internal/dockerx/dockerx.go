// Package dockerx wraps the Docker API surface acmed needs: listing labeled
// containers, inspecting mounts, watching events, running reload commands and
// signalling containers.
package dockerx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Mount is a container mount point (the fields delivery needs).
type Mount struct {
	Source      string
	Destination string
}

// Container is the subset of container state acmed uses.
type Container struct {
	ID     string
	Name   string
	Labels map[string]string
	Mounts []Mount
}

// Client is the Docker access interface, fake-able in tests.
type Client interface {
	// List returns all running containers. acmed labels are parsed from the
	// result; Docker's label filter matches exact keys only, so prefix
	// filtering is not possible.
	List(ctx context.Context) ([]Container, error)
	// Events returns a container-event stream: one signal per event, plus a
	// terminal error. Callers resync on any signal.
	Events(ctx context.Context, since time.Time) (<-chan struct{}, <-chan error)
	Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (int, string, error)
	Kill(ctx context.Context, id string, signal string) error
	Self(ctx context.Context) (Container, bool)
	Close() error
}

type dockerClient struct {
	cli *client.Client
}

// New connects to the Docker daemon at host, using the standard environment
// (DOCKER_TLS_VERIFY, DOCKER_CERT_PATH) for TLS. API-version negotiation is on
// by default. An empty host falls back to the SDK's own DOCKER_HOST handling.
func New(host string) (Client, error) {
	opts := []client.Opt{client.FromEnv}
	if host != "" {
		opts = append(opts, client.WithHost(host))
	}
	cli, err := client.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &dockerClient{cli: cli}, nil
}

func (d *dockerClient) Close() error { return d.cli.Close() }

func (d *dockerClient) List(ctx context.Context) ([]Container, error) {
	res, err := d.cli.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	out := make([]Container, 0, len(res.Items))
	for _, s := range res.Items {
		out = append(out, fromSummary(s))
	}
	return out, nil
}

func (d *dockerClient) Events(ctx context.Context, since time.Time) (<-chan struct{}, <-chan error) {
	filters := client.Filters{}.
		Add("type", "container").
		Add("event", "start", "die", "destroy", "rename")
	res := d.cli.Events(ctx, client.EventsListOptions{
		Since:   fmt.Sprintf("%d", since.Unix()),
		Filters: filters,
	})
	out := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errs)
		for {
			select {
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			case _, ok := <-res.Messages:
				if !ok {
					errs <- fmt.Errorf("event stream closed")
					return
				}
				out <- struct{}{}
			case err, ok := <-res.Err:
				if ok && err != nil {
					errs <- err
				} else {
					errs <- fmt.Errorf("event stream ended")
				}
				return
			}
		}
	}()
	return out, errs
}

func (d *dockerClient) Exec(ctx context.Context, id string, cmd []string, timeout time.Duration) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	created, err := d.cli.ExecCreate(ctx, id, client.ExecCreateOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		TTY:          false,
	})
	if err != nil {
		return -1, "", fmt.Errorf("exec create: %w", err)
	}

	attached, err := d.cli.ExecAttach(ctx, created.ID, client.ExecAttachOptions{TTY: false})
	if err != nil {
		return -1, "", fmt.Errorf("exec attach: %w", err)
	}
	defer attached.Close()

	var stdout, stderr bytes.Buffer
	_, _ = stdcopy.StdCopy(&stdout, &stderr, attached.Reader)

	exitCode, ierr := d.waitExec(ctx, created.ID)
	out := stdout.String()
	if stderr.Len() > 0 {
		out += stderr.String()
	}
	if ierr != nil {
		return exitCode, out, ierr
	}
	if exitCode != 0 {
		return exitCode, out, fmt.Errorf("command exited with code %d", exitCode)
	}
	return 0, out, nil
}

func (d *dockerClient) waitExec(ctx context.Context, execID string) (int, error) {
	for {
		res, err := d.cli.ExecInspect(ctx, execID, client.ExecInspectOptions{})
		if err != nil {
			return -1, fmt.Errorf("exec inspect: %w", err)
		}
		if !res.Running {
			return res.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *dockerClient) Kill(ctx context.Context, id string, signal string) error {
	if _, err := d.cli.ContainerKill(ctx, id, client.ContainerKillOptions{Signal: signal}); err != nil {
		return fmt.Errorf("kill %s (%s): %w", id, signal, err)
	}
	return nil
}

func (d *dockerClient) Self(ctx context.Context) (Container, bool) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return Container{}, false
	}
	res, err := d.cli.ContainerInspect(ctx, hostname, client.ContainerInspectOptions{})
	if err != nil {
		return Container{}, false
	}
	return fromInspect(res.Container), true
}

func fromSummary(s container.Summary) Container {
	name := ""
	if len(s.Names) > 0 {
		name = trimName(s.Names[0])
	}
	return Container{
		ID:     s.ID,
		Name:   name,
		Labels: s.Labels,
		Mounts: convertMounts(s.Mounts),
	}
}

func fromInspect(c container.InspectResponse) Container {
	var labels map[string]string
	if c.Config != nil {
		labels = c.Config.Labels
	}
	return Container{
		ID:     c.ID,
		Name:   trimName(c.Name),
		Labels: labels,
		Mounts: convertMounts(c.Mounts),
	}
}

func convertMounts(in []container.MountPoint) []Mount {
	out := make([]Mount, 0, len(in))
	for _, m := range in {
		out = append(out, Mount{
			Source:      m.Source,
			Destination: m.Destination,
		})
	}
	return out
}

func trimName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	}
	return name
}
