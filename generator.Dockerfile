FROM golang:1.24.3-alpine@sha256:b4f875e650466fa0fe62c6fd3f02517a392123eea85f1d7e69d85f780e4db1c1 AS base
FROM base AS builder

WORKDIR /build

COPY cmd/beyla-genfiles/beyla_genfiles.go .
COPY go.mod go.mod
COPY go.sum go.sum
RUN go build -o beyla_genfiles beyla_genfiles.go

FROM base AS dist

WORKDIR /src

ARG EBPF_VER

RUN apk add clang llvm19 wget
RUN apk cache purge
RUN go install github.com/cilium/ebpf/cmd/bpf2go@$EBPF_VER
COPY --from=builder /build/beyla_genfiles /go/bin

RUN cat <<EOF > /generate.sh
#!/bin/sh
export GOCACHE=/tmp
export GOMODCACHE=/tmp/go-mod-cache
export BPF2GO=bpf2go
export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
export BEYLA_GENFILES_RUN_LOCALLY=1
export BEYLA_GENFILES_MODULE_ROOT="/src"
beyla_genfiles
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]

