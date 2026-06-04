// Command isoboxd is the isobox control-plane daemon: an HTTP API that runs
// untrusted code in gVisor-isolated, resource-capped, ephemeral sandboxes.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/siinghd/isobox/internal/api"
	"github.com/siinghd/isobox/internal/auth"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/memory"
	"github.com/siinghd/isobox/internal/obs"
	"github.com/siinghd/isobox/internal/queue"
	"github.com/siinghd/isobox/internal/reaper"
	"github.com/siinghd/isobox/internal/registry"
	"github.com/siinghd/isobox/internal/sched"
	"github.com/siinghd/isobox/internal/session"
)

func main() {
	obs.Setup(env("ISOBOX_LOG_LEVEL", "info"))

	addr := env("ISOBOX_ADDR", "127.0.0.1:8090")
	regPath := firstExisting(
		os.Getenv("ISOBOX_REGISTRY"),
		"internal/registry/registry.yaml",
		"/etc/isobox/registry.yaml",
	)
	reg, err := registry.Load(regPath)
	if err != nil {
		slog.Error("load registry", "path", regPath, "err", err)
		os.Exit(1)
	}
	slog.Info("registry loaded", "path", regPath, "languages", len(reg.All()))

	exec := executor.Detect()
	// gv is the CONCRETE gVisor backend when present. It is passed UNCHANGED to the
	// session manager and kernel engine (which type-assert *Gvisor); only the
	// one-shot /execute path may be wrapped by the warm pool below. Keeping the
	// concrete value out here avoids accidentally shadowing it with the wrapper and
	// silently disabling kernel sessions.
	gv, _ := exec.(*executor.Gvisor)
	// Opt-in filtered egress for network:true requests (default on; off if the
	// host has no egress network configured or the operator disables it).
	if gv != nil {
		g := gv
		if v := os.Getenv("ISOBOX_ALLOW_NETWORK"); v == "0" || v == "false" {
			g.AllowNetwork = false
		}
		if v := os.Getenv("ISOBOX_EGRESS_NETWORK"); v != "" {
			g.EgressNetwork = v
		}
		// Empty value disables the fail-closed firewall heartbeat check (operator
		// takes responsibility for the egress firewall).
		if v, ok := os.LookupEnv("ISOBOX_EGRESS_SENTINEL"); ok {
			g.Sentinel = v
		}
		if v := envInt("ISOBOX_SENTINEL_MAX_AGE_SEC", 0); v > 0 {
			g.SentinelMaxAge = time.Duration(v) * time.Second
		}
		slog.Info("network mode", "allowed", g.AllowNetwork, "egressNetwork", g.EgressNetwork, "sentinel", g.Sentinel)
	}
	if err := exec.HealthCheck(context.Background()); err != nil {
		slog.Warn("backend health check failed at startup (continuing; /readyz will report)", "backend", exec.Name(), "err", err)
	}

	// Auth keystore: resolve API keys to server-derived tenant ids. FAIL CLOSED —
	// if a key source is EXPLICITLY configured but yields zero usable keys (typo'd
	// path, empty/whitespace file, unreadable file), exit rather than silently
	// dropping to open/public mode (which would be a full auth bypass). Only a
	// fully-UNSET config may use open mode.
	keys := loadKeyStore()

	// Phase 5 WARM POOL (default OFF, ISOBOX_WARMPOOL_PYTHON=0). When >0 and the
	// backend is gVisor, pre-boot N hardened `sleep infinity` python containers and
	// serve poolable one-shot jobs by `docker exec` into them (single-use: removed +
	// async-replenished after each job). The pool WRAPS gv only for the one-shot
	// /execute path (srv.Exec); the SAME concrete gv is still handed to sessions and
	// the kernel engine below, so those paths are byte-for-byte unchanged. With size
	// 0 the wrapper is a pure passthrough — defaults => identical behaviour.
	var oneShotExec executor.Executor = exec
	var pool *executor.WarmPool
	warmSize := envInt("ISOBOX_WARMPOOL_PYTHON", 0)
	if warmSize > 0 && gv != nil {
		plang, ok := reg.Resolve("python", "")
		if !ok {
			slog.Warn("warm pool requested but python runtime not in registry; disabling")
		} else {
			pl := plang.DefaultLimits()
			pool = executor.NewWarmPool(gv, executor.WarmPoolConfig{
				Size:      warmSize,
				Image:     plang.Image,
				MemBytes:  pl.MemoryBytes,
				CPUs:      pl.CPUs,
				Pids:      pl.Pids,
				ScratchMB: plang.ScratchMB,
			})
			oneShotExec = pool
			pool.Prime(context.Background())
			slog.Info("warm pool enabled", "image", plang.Image, "size", warmSize, "ready", pool.Ready())
		}
	} else if warmSize > 0 {
		slog.Warn("warm pool requested but backend is not gVisor; disabling")
	}

	srv := &api.Server{
		Reg:         reg,
		Exec:        oneShotExec,
		Pool:        pool,
		Sema:        sched.New(envInt("ISOBOX_CONCURRENCY", 4)),
		Keys:        keys,
		AcquireWait: time.Duration(envInt("ISOBOX_ACQUIRE_WAIT_MS", 2000)) * time.Millisecond,
		// ISOBOX_REQUIRE_AUTH=1 rejects keyless requests entirely. ISOBOX_MEMORY_REQUIRE_KEY=1
		// keeps /execute + /v1/sessions open but requires an API key for /v1/memory + /v1/volumes.
		RequireAuth:      envBool("ISOBOX_REQUIRE_AUTH", false),
		MemoryRequireKey: envBool("ISOBOX_MEMORY_REQUIRE_KEY", false),
	}
	if keys.Len() == 0 {
		slog.Warn("AUTH OPEN MODE: no API keys configured — all callers share the single 'public' tenant")
	} else {
		slog.Info("auth enabled", "keys", keys.Len())
	}

	// Stateful sessions (v2): a filesystem session is a per-session host dir under
	// ISOBOX_SESSIONS_ROOT, bind-mounted RW at /workspace. Shares the global
	// concurrency gate. Disabled gracefully if the root isn't writable.
	sessRoot := env("ISOBOX_SESSIONS_ROOT", "/var/lib/isobox/sessions")
	if mgr, err := session.NewManager(exec, reg, srv.Sema, session.Config{
		Root:          sessRoot,
		DiskQuota:     int64(envInt("ISOBOX_SESSION_DISK_MB", 512)) << 20,
		GlobalDiskMax: int64(envInt("ISOBOX_SESSIONS_DISK_MAX_GB", 10)) << 30,
		MaxSessions:   envInt("ISOBOX_MAX_SESSIONS", 200),
		TTL:           time.Duration(envInt("ISOBOX_SESSION_TTL_SEC", 86400)) * time.Second,
	}); err != nil {
		slog.Warn("stateful sessions disabled", "root", sessRoot, "err", err)
	} else {
		srv.Sessions = mgr
		slog.Info("stateful sessions enabled", "root", sessRoot,
			"diskMaxGB", envInt("ISOBOX_SESSIONS_DISK_MAX_GB", 10), "maxSessions", envInt("ISOBOX_MAX_SESSIONS", 200))
	}

	// Phase 4: LIVE KERNEL sessions (type="kernel") — one long-lived, fully-sandboxed
	// python-slim container per session running a persistent REPL harness, so
	// variables/imports survive across exec steps (Code-Interpreter parity). Gated to
	// the gVisor backend (NewKernelEngine returns ok=false otherwise) and to having a
	// session manager. A SECOND limiter (KernelSlots, ISOBOX_KERNEL_SLOTS default 6)
	// bounds RESIDENT kernels independent of the exec concurrency Sema.
	if kEngine, ok := session.NewKernelEngine(exec, session.KernelConfig{
		Slots:       envInt("ISOBOX_KERNEL_SLOTS", 6),
		MemoryBytes: int64(envInt("ISOBOX_KERNEL_MEM_MB", 128)) << 20,
		OutputBytes: int64(envInt("ISOBOX_KERNEL_OUTPUT_BYTES", 65536)),
		IdleTTL:     time.Duration(envInt("ISOBOX_KERNEL_IDLE_SEC", 1800)) * time.Second,
		MaxLifetime: time.Duration(envInt("ISOBOX_KERNEL_MAX_LIFE_SEC", 14400)) * time.Second,
		MaxStepMs:   envInt("ISOBOX_KERNEL_MAX_STEP_MS", 60000),
	}); ok && srv.Sessions != nil {
		srv.Sessions.Kernels = kEngine
		slog.Info("kernel sessions enabled", "slots", kEngine.Slots.Max())
	} else {
		slog.Info("kernel sessions disabled (non-gVisor backend or no session manager)")
	}

	// Phase 3 tier-2: persistent filesystem VOLUMES (/memory bind-mount). The
	// statfs free-disk floor (ISOBOX_MIN_FREE_DISK_GB) is the unprivileged backstop
	// against exhausting the shared 35G disk — set it for ALL of sessions, volumes
	// and KV so no single tier can push the disk to zero.
	minFree := int64(envInt("ISOBOX_MIN_FREE_DISK_GB", 4)) << 30
	volRoot := env("ISOBOX_VOL_ROOT", "/var/lib/isobox/vol")
	volMgr, err := memory.NewManager(memory.Config{
		Root:            volRoot,
		DiskQuota:       int64(envInt("ISOBOX_VOL_DISK_MB", 512)) << 20,
		GlobalDiskMax:   int64(envInt("ISOBOX_VOL_DISK_MAX_GB", 8)) << 30,
		MaxVolPerTenant: envInt("ISOBOX_MAX_VOL_PER_TENANT", 100),
		MinFreeBytes:    minFree,
	})
	if err != nil {
		slog.Warn("volumes disabled", "root", volRoot, "err", err)
	} else {
		srv.Volumes = volMgr
		slog.Info("volumes enabled", "root", volRoot, "count", volMgr.Count())
		// Release any RW volume hold when a session is destroyed OR swept, so a
		// crashed/swept session never leaks the lock until restart.
		if srv.Sessions != nil {
			srv.Sessions.OnDrop = volMgr.ReleaseAll
		}
	}

	// Phase 3 tier-3: structured KV MEMORY (one <tenant>.bolt per tenant).
	kvDir := env("ISOBOX_KV_DIR", "/var/lib/isobox/kv")
	kvStore, err := memory.Open(kvDir, minFree)
	if err != nil {
		slog.Warn("kv memory disabled", "dir", kvDir, "err", err)
	} else {
		srv.Memory = kvStore
		slog.Info("kv memory enabled", "dir", kvDir)
	}

	// Phase 5 QUEUE SEAM (default "inproc"). inproc => the buffered /execute path runs
	// jobs locally through srv.Runner() (acquire Sema -> Exec.Execute -> release),
	// byte-for-byte today's behaviour. "valkey" => a Redis-Streams job bus so a worker
	// POOL can share the stream; per-host Sema stays local. Valkey unreachable => log +
	// fall back to inproc (never blocks startup). The local Runner is the same either
	// way, so a single node behaves identically regardless of driver.
	runner := srv.Runner()
	switch strings.ToLower(env("ISOBOX_QUEUE", "inproc")) {
	case "valkey", "redis":
		q := queue.NewValkey(queue.ValkeyConfig{
			Addr:     env("ISOBOX_VALKEY_ADDR", "127.0.0.1:6379"),
			Password: os.Getenv("ISOBOX_VALKEY_PASSWORD"),
			TLS:      env("ISOBOX_VALKEY_TLS", "1") != "0",
			// Default-skip TLS verification: the broker is a self-signed loopback
			// endpoint. Set ISOBOX_VALKEY_TLS_VERIFY=1 to enforce chain/hostname checks.
			SkipVerify: env("ISOBOX_VALKEY_TLS_VERIFY", "0") == "0",
			Runner:     runner,
		}, reg)
		if q != nil {
			srv.Queue = q
			q.StartWorkers(context.Background(), envInt("ISOBOX_VALKEY_WORKERS", 2))
			slog.Info("queue driver enabled", "driver", "valkey", "addr", env("ISOBOX_VALKEY_ADDR", "127.0.0.1:6379"))
		} else {
			srv.Queue = queue.NewInProc(runner)
			slog.Warn("valkey queue unreachable; fell back to inproc")
		}
	default:
		srv.Queue = queue.NewInProc(runner)
		slog.Info("queue driver enabled", "driver", "inproc")
	}

	handler := srv.Router(api.Config{
		AcquireWait: srv.AcquireWait,
		RatePerMin:  envInt("ISOBOX_RATE_PER_MIN", 30),
		RateBurst:   envInt("ISOBOX_RATE_BURST", 10),
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP hot-reloads the language registry without dropping in-flight work.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := reg.Reload(regPath); err != nil {
				slog.Error("registry reload failed (keeping previous)", "err", err)
			} else {
				slog.Info("registry reloaded", "languages", len(reg.All()))
			}
		}
	}()

	go reaper.Run(ctx, 60*time.Second)

	// Sweep sessions frequently: enforce idle-TTL + per-session AND global disk
	// ceilings against actual disk usage (bounds the direct-write blast radius).
	// One 30s ticker drives all three Phase-3 sweeps: session idle/quota drop,
	// volume orphan GC + used-counter refresh, and KV TTL reclaim across open
	// handles. Cheap and bounded; mirrors the existing session-sweep cadence.
	if srv.Sessions != nil || srv.Volumes != nil || srv.Memory != nil {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if srv.Sessions != nil {
						srv.Sessions.Sweep(ctx)
						// Reap resident kernels idle past IdleTTL or older than MaxLifetime
						// (owned by the kernel's own lastUsed, not the disk-based Sweep).
						srv.Sessions.SweepKernels()
					}
					if srv.Volumes != nil {
						srv.Volumes.Sweep()
					}
					if srv.Memory != nil {
						if n, err := srv.Memory.SweepExpired(); err != nil {
							slog.Warn("kv sweep", "err", err)
						} else if n > 0 {
							slog.Debug("kv sweep reclaimed", "records", n)
						}
					}
				}
			}
		}()
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // unbounded: SSE streams outlive a fixed write deadline
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("isoboxd listening", "addr", addr, "backend", exec.Name(), "concurrency", srv.Sema.Max())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	// Stop queue workers and release the broker connection (no-op for inproc).
	if srv.Queue != nil {
		_ = srv.Queue.Close()
	}
	// Tear down warm-pool containers so none outlives the daemon (no-op when disabled).
	if pool != nil {
		pool.Close()
	}
	// Tear down every resident kernel container so none outlives the daemon (a
	// kernel is status=running by design, so the exited-only reaper never reaps it).
	if srv.Sessions != nil && srv.Sessions.Kernels != nil {
		srv.Sessions.Kernels.DestroyAll()
	}
	// Close the KV store so every tenant's bbolt handle (flock + mmap) is released
	// cleanly; volume/session data is plain files and needs no explicit close.
	if srv.Memory != nil {
		if err := srv.Memory.Close(); err != nil {
			slog.Warn("kv close", "err", err)
		}
	}
}

// loadKeyStore builds the auth keystore and FAILS CLOSED on misconfiguration.
// Precedence: ISOBOX_API_KEYS_FILE (newline/comma list) > ISOBOX_API_KEYS
// (comma list) > ISOBOX_API_KEY (single). If ANY of these is set but yields zero
// usable keys (or the file can't be read), os.Exit(1) — only a fully-UNSET
// config falls through to open/public mode.
func loadKeyStore() *auth.KeyStore {
	if path := os.Getenv("ISOBOX_API_KEYS_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			slog.Error("ISOBOX_API_KEYS_FILE set but unreadable — refusing to start in open mode", "path", path, "err", err)
			os.Exit(1)
		}
		ks := auth.NewKeyStore(splitKeys(string(b)))
		if ks.Len() == 0 {
			slog.Error("ISOBOX_API_KEYS_FILE set but contained no usable keys — refusing to start in open mode", "path", path)
			os.Exit(1)
		}
		return ks
	}
	if raw := os.Getenv("ISOBOX_API_KEYS"); raw != "" {
		ks := auth.NewKeyStore(splitKeys(raw))
		if ks.Len() == 0 {
			slog.Error("ISOBOX_API_KEYS set but contained no usable keys — refusing to start in open mode")
			os.Exit(1)
		}
		return ks
	}
	if raw := os.Getenv("ISOBOX_API_KEY"); raw != "" {
		ks := auth.NewKeyStore([]string{raw})
		if ks.Len() == 0 {
			slog.Error("ISOBOX_API_KEY set but blank — refusing to start in open mode")
			os.Exit(1)
		}
		return ks
	}
	return auth.NewKeyStore(nil) // fully unset -> open/public mode
}

// splitKeys splits a keys blob on newlines and commas; NewKeyStore trims and
// drops blanks.
func splitKeys(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == '\t'
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	switch os.Getenv(key) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// fall back to the last candidate so the error message is useful
	if len(paths) > 0 {
		return paths[len(paths)-1]
	}
	return ""
}
