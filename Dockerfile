FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src

COPY sftp/go.mod sftp/go.sum* ./sftp/
WORKDIR /src/sftp
RUN go mod download

WORKDIR /src
COPY sftp/ ./sftp/
WORKDIR /src/sftp

ARG VERSION=dev
# Cross-compile on the build host ($BUILDPLATFORM above) rather than under
# QEMU emulation: multi-arch release builds of the arm64 image were slow
# enough to hit the release job timeout.
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/sftp .

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/sftp /sftp
USER 65532:65532
# SFTP listens on 2222 by default (Helm sftp.port); the Service maps it.
EXPOSE 2222
ENTRYPOINT ["/sftp"]
