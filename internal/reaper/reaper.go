// Package reaper periodically force-removes orphaned sandbox containers — ones a
// crash or hard kill left behind before the executor's deferred cleanup ran.
// Sandboxes are identified by the isobox.managed=true label, so the sweep can
// never touch a neighbouring service's containers.
package reaper

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

const label = "isobox.managed=true"

// Run sweeps orphaned sandboxes every interval until ctx is cancelled.
func Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep(ctx)
		}
	}
}

func sweep(ctx context.Context) {
	// Only containers that have already exited are safe to remove; a running one
	// is an in-flight execution the executor still owns.
	out, err := exec.CommandContext(ctx, "docker", "ps", "-aq",
		"--filter", "label="+label, "--filter", "status=exited").Output()
	if err != nil {
		return
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return
	}
	args := append([]string{"rm", "-f"}, ids...)
	if err := exec.CommandContext(ctx, "docker", args...).Run(); err != nil {
		slog.Warn("reaper: failed to remove orphans", "count", len(ids), "err", err)
		return
	}
	slog.Info("reaper: removed orphaned sandboxes", "count", len(ids))
}
