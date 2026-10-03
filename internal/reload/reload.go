// Package reload triggers a target container to pick up renewed certificates.
package reload

import (
	"context"
	"time"

	"github.com/NathanAdhitya/acme-docker-companion/internal/dockerx"
)

// DefaultTimeout bounds a reload command.
const DefaultTimeout = 30 * time.Second

// Exec runs a shell command inside the target container.
func Exec(ctx context.Context, cli dockerx.Client, containerID, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	_, out, err := cli.Exec(ctx, containerID, []string{"/bin/sh", "-c", command}, timeout)
	return out, err
}

// Signal sends a signal to PID 1 of the target container.
func Signal(ctx context.Context, cli dockerx.Client, containerID, signal string) error {
	return cli.Kill(ctx, containerID, signal)
}
