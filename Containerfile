# syntax=docker/dockerfile:1

# The wheel is built in a disposable stage; the runtime carries only the
# installed wheel and its pinned runtime dependencies.
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY privilege_broker ./privilege_broker
RUN python -m pip install --no-cache-dir --disable-pip-version-check build \
 && python -m build --wheel --outdir /dist

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TMPDIR=/tmp

# The approval service signs SSH certificates by running ssh-keygen, so the
# executable is a runtime dependency, not a host-side one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 broker \
 && useradd --system --uid 10001 --gid broker --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin broker

COPY --from=build /dist/*.whl /tmp/wheel/
RUN python -m pip install --no-cache-dir /tmp/wheel/*.whl \
 && rm -rf /tmp/wheel

USER 10001:10001
EXPOSE 8940

# A TCP probe keeps the healthcheck independent of the HTTP route table.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8940), 3).close()"]

# The service factory reads its configuration from the environment. Binding
# loopback is deliberate: the container runs with host networking behind the
# host's TLS-terminating proxy, exactly as the unit it replaces did.
# --no-proxy-headers keeps the real loopback peer address: the mTLS extractor
# requires the connecting frontend to be loopback and rewrites would break it.
ENTRYPOINT ["uvicorn", "privilege_broker.pve.service:create_broker_app_from_env", "--factory", "--host", "127.0.0.1", "--port", "8940", "--no-proxy-headers"]
