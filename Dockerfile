# Assay ships one image containing four binaries: the operator manager, the
# in-pod scan runner, the console API server, and the standalone CLI. Scan Jobs mount the same image
# for their fetch and publish steps, so there is a single artifact to mirror
# into an air-gapped registry, and `docker run --entrypoint /assay` gives the
# same scanner to anyone without a cluster.
# Must be at least the go directive in go.mod, which oras-go pins to 1.25.
FROM registry.access.redhat.com/ubi9/go-toolset:1.25 AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w" -o assay-manager ./cmd/manager && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w" -o assay-runner ./cmd/runner && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w -X main.version=${VERSION}" -o assay ./cmd/assay && \
      go build -a -ldflags="-s -w" -o assay-api ./cmd/api

FROM registry.access.redhat.com/ubi9/ubi-micro:latest

WORKDIR /

# The CA bundle. ubi-micro ships no trust store at all, so without this every
# HTTPS call the operator makes fails with "certificate signed by unknown
# authority" — the Model Registry, Hugging Face, S3, all of it. It is copied
# from the builder rather than installed, because ubi-micro has no package
# manager to install it with.
COPY --from=builder /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /workspace/assay-manager /assay-manager
COPY --from=builder /workspace/assay-runner /assay-runner
COPY --from=builder /workspace/assay-api /assay-api
COPY --from=builder /workspace/assay /assay

# 65532 is the conventional nonroot UID. OpenShift assigns its own UID from
# the namespace range, which works because the binaries need no writable paths.
USER 65532:65532

ENTRYPOINT ["/assay-manager"]
