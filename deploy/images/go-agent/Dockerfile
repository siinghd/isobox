# isobox go-agent image — Go with a PRE-WARMED build cache. `go run` normally
# recompiles the standard library on every ephemeral run (~14s under gVisor);
# baking a warm GOCACHE and copying it into the writable scratch at run time cuts
# that to a few seconds. The warm cache covers the common stdlib an agent uses
# (fmt, net/http, encoding/json, io, strings, sort, sync, regexp, time, ...).
# Base pinned by digest (THREAT_MODEL control #13) — see python-agent Dockerfile.
FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191
RUN mkdir -p /opt/gocache /opt/go \
 && printf 'package main\nimport("fmt";"os";"strings";"strconv";"sort";"math";"time";"bufio";"errors";"context";"encoding/json";"net/http";"net/url";"io";"regexp";"bytes";"sync";"sync/atomic")\nfunc main(){_=fmt.Sprint;_=os.Args;_=strings.Split;_=strconv.Itoa;_=sort.Ints;_=math.Sqrt;_=time.Now;_=bufio.NewReader;_=errors.New;_=context.Background;b,_:=json.Marshal(1);_=b;_=http.Get;_=url.Parse;_=io.ReadAll;_=regexp.MustCompile;_=bytes.NewBuffer;var m sync.Mutex;_=m;var a atomic.Int64;_=a.Load()}\n' > /tmp/warm.go \
 && GOCACHE=/opt/gocache GOPATH=/opt/go GOFLAGS=-mod=mod go build -o /dev/null /tmp/warm.go \
 && chmod -R a+rX /opt/gocache /opt/go \
 && rm /tmp/warm.go \
 && du -sh /opt/gocache

# Drop privileges by default, matching python-agent (the executor also forces
# --user=65534, so this is belt-and-suspenders against a future flag drop).
USER 65534:65534
