FROM gcr.io/distroless/static:nonroot@sha256:188ddfb9e497f861177352057cb21913d840ecae6c843d39e00d44fa64daa51c
WORKDIR /
COPY proxy proxy
USER 65532:65532

ENTRYPOINT ["/proxy"]
