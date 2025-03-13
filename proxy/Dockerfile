FROM gcr.io/distroless/static:nonroot@sha256:6ec5aa99dc335666e79dc64e4a6c8b89c33a543a1967f20d360922a80dd21f02
WORKDIR /
COPY proxy proxy
USER 65532:65532

ENTRYPOINT ["/proxy"]
