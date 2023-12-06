FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY proxy proxy
USER 65532:65532

ENTRYPOINT ["/proxy"]
