# Build the manager binary
FROM golang:1.17 as builder

WORKDIR /workspace
COPY . .

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go

FROM amazoncorretto:11-alpine
WORKDIR /
COPY --from=builder /workspace/manager .
COPY assets /assets
USER 10000:10000
ENV ASSETS_PATH="/assets"

ENTRYPOINT ["/manager"]
