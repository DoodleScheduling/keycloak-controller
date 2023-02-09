# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM amazoncorretto:11
WORKDIR /
COPY manager manager
USER 65532:65532
COPY assets /assets
ENV ASSETS_PATH="/assets"
ENV USER k8skeycloak-controller

ENTRYPOINT ["/manager"]
