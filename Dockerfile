FROM amazoncorretto:17.0.8
WORKDIR /
COPY manager manager
USER 65532:65532
COPY assets /assets
ENV ASSETS_PATH="/assets"
ENV USER keycloak-controller

ENTRYPOINT ["/manager"]
