FROM debian:trixie-slim@sha256:a717a33469731894e77e912ea7d714e27c2dc38ee6554fd1a3102e92999cfc66 AS build

ARG WHEEL=""
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl libatomic1 \
    && rm -rf /var/lib/apt/lists/*
COPY . /src/
RUN set -eux; \
    if [ -n "${WHEEL}" ]; then \
        /src/install.sh --image --wheel "/src/${WHEEL}"; \
    else \
        /src/install.sh --image; \
    fi; \
    rm -rf /opt/gitmortem/cache /opt/gitmortem/node

FROM debian:trixie-slim@sha256:a717a33469731894e77e912ea7d714e27c2dc38ee6554fd1a3102e92999cfc66

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/gitmortem /opt/gitmortem
COPY docker/entrypoint.sh /usr/local/bin/gitmortem-entrypoint
RUN set -eux; \
    chmod 0755 /usr/local/bin/gitmortem-entrypoint; \
    useradd --system --uid 10001 --user-group --home-dir /data --shell /usr/sbin/nologin gitmortem; \
    install -d -m 0700 -o gitmortem -g gitmortem /data; \
    install -d -m 0755 /repos; \
    find / -xdev -type f -perm /6000 -exec chmod ug-s {} +

USER gitmortem
ENV PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/gitmortem-entrypoint"]
