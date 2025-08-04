FROM gcr.io/distroless/static:nonroot@sha256:cdf4daaf154e3e27cfffc799c16f343a384228f38646928a1513d925f473cb46
WORKDIR /
COPY manager manager
USER 65532:65532

ENTRYPOINT ["/manager"]
