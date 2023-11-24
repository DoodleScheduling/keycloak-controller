FROM amazoncorretto:21.0.1
WORKDIR /
COPY manager manager
USER 65532:65532
COPY assets /assets
ENV ASSETS_PATH="/assets"
ENV USER keycloak-controller

ENTRYPOINT ["/manager"]
