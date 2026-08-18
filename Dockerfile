# Assay ships one image containing two binaries: the operator
# manager and the in-pod scan runner. Scan Jobs mount the same image for their
# fetch and publish steps, so there is a single artifact to mirror into an
# air-gapped registry.
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

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w" -o assay-manager ./cmd/manager && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w" -o assay-runner ./cmd/runner

FROM registry.access.redhat.com/ubi9/ubi-micro:latest

WORKDIR /
COPY --from=builder /workspace/assay-manager /assay-manager
COPY --from=builder /workspace/assay-runner /assay-runner

# 65532 is the conventional nonroot UID. OpenShift assigns its own UID from
# the namespace range, which works because the binaries need no writable paths.
USER 65532:65532

ENTRYPOINT ["/assay-manager"]
