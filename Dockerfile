FROM ubuntu:latest as downloader

ARG RELAY_VERSION=latest
WORKDIR /app

RUN apt-get update && apt-get install -y curl tar unzip && rm -rf /var/lib/apt/lists/*

RUN set -e; \
    if [ "$RELAY_VERSION" = "latest" ]; then \
      RELAY_VERSION=$(curl -s https://api.github.com/repos/RelayCore/relay-server/releases/latest | grep tag_name | cut -d '"' -f 4); \
    fi; \
    set +e; \
    curl -L -o relay-server.tar.gz "https://github.com/RelayCore/relay-server/releases/download/${RELAY_VERSION}/relay-server_${RELAY_VERSION}_linux_amd64.zip"; \
    CURL_STATUS=$$?; \
    if [ $$CURL_STATUS -eq 0 ]; then \
      mkdir bin && unzip relay-server.tar.gz -d bin && mv bin/relay-server /app/relay-server && rm -rf bin relay-server.tar.gz; \
    else \
      echo "Download failed, skipping downloader binary."; \
      touch /app/relay-server; \
    fi

# --- Final image ---
FROM ubuntu:latest

ARG LOCAL_RELAY_PATH
WORKDIR /app

RUN apt-get update && apt-get install -y curl tar unzip && rm -rf /var/lib/apt/lists/*

COPY config.yaml .
RUN mkdir -p /app/uploads

# Try to copy the local binary if it exists (ignore errors)
COPY ${LOCAL_RELAY_PATH:-nonexistent} /app/relay-server-local
COPY --from=downloader /app/relay-server /app/relay-server-downloaded

RUN cat > /app/entrypoint.sh <<'EOF'
#!/bin/sh
set -e
if [ -x /app/relay-server-local ]; then
  cp /app/relay-server-local /app/relay-server
elif [ -x /app/relay-server-downloaded ]; then
  cp /app/relay-server-downloaded /app/relay-server
else
  echo "No relay-server binary found. Exiting."
  exit 1
fi
chmod +x /app/relay-server
exec /app/relay-server
EOF

RUN chmod +x /app/entrypoint.sh

EXPOSE 36954
ENTRYPOINT ["/app/entrypoint.sh"]