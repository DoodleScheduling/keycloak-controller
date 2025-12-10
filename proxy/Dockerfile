FROM gcr.io/distroless/static:nonroot@sha256:2b7c93f6d6648c11f0e80a48558c8f77885eb0445213b8e69a6a0d7c89fc6ae4
WORKDIR /
COPY proxy proxy
USER 65532:65532

ENTRYPOINT ["/proxy"]
