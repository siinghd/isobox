package queue

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/registry"
)

// Valkey is the OPTIONAL multi-node driver. It distributes buffered jobs over a
// Redis-Streams job bus (Valkey is Redis-compatible) so any worker in a pool can
// pick one up:
//
//   - Submit: XADD isobox:jobs, then BLPOP the per-job result list (TTL-bounded).
//   - Workers: XREADGROUP GROUP workers, run the job LOCALLY via the Runner (so
//     per-host concurrency stays local), then LPUSH the result + XACK.
//   - Reaper: XAUTOCLAIM reclaims jobs whose worker died mid-flight and re-runs
//     them. At-least-once is safe here: a default job runs --network=none and is
//     therefore idempotent (re-running recomputes the same pure result).
//
// SCOPE is deliberately small — the seam plus a working driver, not a full job
// system. Construction NEVER blocks startup: NewValkey returns nil if the broker
// can't be reached on a short-timeout PING, and main falls back to inproc.
type Valkey struct {
	rdb    *redis.Client
	reg    *registry.Registry
	runner Runner

	stream    string
	group     string
	consumer  string
	resultTTL time.Duration

	cancel context.CancelFunc
}

// ValkeyConfig parameterises the driver.
type ValkeyConfig struct {
	Addr       string
	Password   string
	TLS        bool
	SkipVerify bool // skip TLS chain/hostname verification (self-signed loopback broker)
	Runner     Runner
}

const (
	valkeyStream    = "isobox:jobs"
	valkeyGroup     = "workers"
	valkeyResultTTL = 60 * time.Second
	valkeyConnWait  = 2 * time.Second
)

// NewValkey dials the broker and ensures the consumer group exists. Returns nil
// (NOT an error) if the broker is unreachable, so the caller logs and falls back to
// inproc without blocking startup.
func NewValkey(cfg ValkeyConfig, reg *registry.Registry) *Valkey {
	opt := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
	}
	if cfg.TLS {
		// The broker terminates TLS on a LOOPBACK endpoint with a self-signed cert
		// (CN=redis.hsingh.app on 127.0.0.1). Strict chain/hostname verification would
		// reject it (wrong CN for 127.0.0.1, self-signed, possibly expired) and the
		// driver would silently fall back to inproc — defeating the point. The trust
		// boundary here is "is this the local broker", which loopback + requirepass
		// already establish; the TLS layer is for on-wire confidentiality, not peer
		// auth. So skip chain/hostname verification (configurable via ISOBOX_VALKEY_TLS_VERIFY).
		opt.TLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.SkipVerify,
		}
	}
	rdb := redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), valkeyConnWait)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Warn("valkey: PING failed at startup", "addr", cfg.Addr, "err", err)
		_ = rdb.Close()
		return nil
	}

	v := &Valkey{
		rdb:       rdb,
		reg:       reg,
		runner:    cfg.Runner,
		stream:    valkeyStream,
		group:     valkeyGroup,
		consumer:  "isobox-" + uuid.NewString()[:8],
		resultTTL: valkeyResultTTL,
	}
	// MKSTREAM creates the stream+group atomically; BUSYGROUP means it already exists.
	if err := rdb.XGroupCreateMkStream(context.Background(), v.stream, v.group, "0").Err(); err != nil &&
		err.Error() != "BUSYGROUP Consumer Group name already exists" {
		slog.Warn("valkey: XGROUP CREATE", "err", err)
		// Non-fatal: the group may exist; workers will surface a hard error if not.
	}
	return v
}

func (v *Valkey) Name() string { return "valkey" }

// Submit enqueues the job and waits (request-ctx bounded) for whichever worker
// produces the result. The result is delivered via a per-job list with the same TTL
// as the stream entry, so a crashed submitter can't leak Redis memory.
func (v *Valkey) Submit(ctx context.Context, j Job) (executor.Result, error) {
	if j.ID == "" {
		j.ID = uuid.NewString()
	}
	payload, err := json.Marshal(j)
	if err != nil {
		return executor.Result{}, fmt.Errorf("marshal job: %w", err)
	}
	if err := v.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: v.stream,
		Values: map[string]any{"job": payload},
	}).Err(); err != nil {
		return executor.Result{}, fmt.Errorf("xadd: %w", err)
	}

	// Wait for the result on a per-job list. BLPOP blocks up to the request deadline.
	resKey := "isobox:res:" + j.ID
	deadline := time.Now().Add(v.resultTTL)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return executor.Result{}, fmt.Errorf("valkey: result timeout for job %s", j.ID)
		}
		// Cap each BLPOP so ctx cancellation is observed promptly.
		block := remain
		if block > time.Second {
			block = time.Second
		}
		out, err := v.rdb.BLPop(ctx, block, resKey).Result()
		if err == redis.Nil {
			if ctx.Err() != nil {
				return executor.Result{}, ctx.Err()
			}
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return executor.Result{}, ctx.Err()
			}
			return executor.Result{}, fmt.Errorf("blpop: %w", err)
		}
		// out = [key, value]
		var rr resultEnvelope
		if err := json.Unmarshal([]byte(out[1]), &rr); err != nil {
			return executor.Result{}, fmt.Errorf("unmarshal result: %w", err)
		}
		if rr.Err != "" {
			return rr.Result, fmt.Errorf("%s", rr.Err)
		}
		return rr.Result, nil
	}
}

// resultEnvelope wraps a Result + optional error string for transport.
type resultEnvelope struct {
	Result executor.Result `json:"result"`
	Err    string          `json:"err,omitempty"`
}

// StartWorkers launches n consumer goroutines draining the stream plus one reaper.
// They live for the process (ctx is context.Background from main); Close cancels.
func (v *Valkey) StartWorkers(ctx context.Context, n int) {
	if n <= 0 {
		n = 2
	}
	wctx, cancel := context.WithCancel(ctx)
	v.cancel = cancel
	for i := 0; i < n; i++ {
		go v.worker(wctx)
	}
	go v.reaper(wctx)
}

// worker blocks on XREADGROUP, runs each claimed job locally, publishes the result,
// and XACKs. A panic in a single job must not kill the worker loop.
func (v *Valkey) worker(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		streams, err := v.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    v.group,
			Consumer: v.consumer,
			Streams:  []string{v.stream, ">"},
			Count:    1,
			Block:    time.Second,
		}).Result()
		if err == redis.Nil {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Second) // broker hiccup; back off and retry
			continue
		}
		for _, st := range streams {
			for _, msg := range st.Messages {
				v.process(ctx, msg)
			}
		}
	}
}

// process runs one stream message to completion and ACKs it.
func (v *Valkey) process(ctx context.Context, msg redis.XMessage) {
	defer func() {
		// ACK unconditionally after we've published a result (or failed to decode):
		// a poison message must not be redelivered forever. The result/err is already
		// on the per-job list for the submitter.
		_ = v.rdb.XAck(ctx, v.stream, v.group, msg.ID).Err()
	}()

	raw, _ := msg.Values["job"].(string)
	var j Job
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		slog.Warn("valkey: undecodable job; acking", "id", msg.ID, "err", err)
		return
	}
	res, runErr := v.runner.Run(ctx, j.Spec)
	env := resultEnvelope{Result: res}
	if runErr != nil {
		env.Err = runErr.Error()
	}
	payload, _ := json.Marshal(env)
	resKey := "isobox:res:" + j.ID
	pipe := v.rdb.Pipeline()
	pipe.RPush(ctx, resKey, payload)
	pipe.Expire(ctx, resKey, v.resultTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		slog.Warn("valkey: publish result", "job", j.ID, "err", err)
	}
}

// reaper periodically XAUTOCLAIMs jobs idle longer than the result TTL (their
// worker died mid-flight) so they get re-run by a live worker. At-least-once is
// safe for idempotent (network-off) jobs.
func (v *Valkey) reaper(ctx context.Context) {
	t := time.NewTicker(v.resultTTL)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			msgs, _, err := v.rdb.XAutoClaim(ctx, &redis.XAutoClaimArgs{
				Stream:   v.stream,
				Group:    v.group,
				Consumer: v.consumer,
				MinIdle:  v.resultTTL,
				Start:    "0",
				Count:    16,
			}).Result()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			for _, msg := range msgs {
				v.process(ctx, msg)
			}
		}
	}
}

// Close stops the workers and releases the broker connection.
func (v *Valkey) Close() error {
	if v.cancel != nil {
		v.cancel()
	}
	return v.rdb.Close()
}
