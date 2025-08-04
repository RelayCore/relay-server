FROM alpine:latest

ARG RELAY_VERSION=latest
ARG LOCAL_RELAY_PATH
WORKDIR /app

RUN apk add --no-cache curl tar unzip

COPY config.yaml .
COPY uploads/ ./uploads/

RUN if [ -n "$LOCAL_RELAY_PATH" ]; then \
      cp "$LOCAL_RELAY_PATH" /app/relay-server && chmod +x /app/relay-server; \
    else \
      if [ "$RELAY_VERSION" = "latest" ]; then \
        RELAY_VERSION=$(curl -s https://api.github.com/repos/RelayCore/relay-server/releases/latest | grep tag_name | cut -d '"' -f 4); \
      fi && \
      curl -L -o relay-server.tar.gz "https://github.com/RelayCore/relay-server/releases/download/${RELAY_VERSION}/relay-server_${RELAY_VERSION}_linux_amd64.zip" && \
      mkdir bin && \
      unzip relay-server.tar.gz -d bin && \
      mv bin/relay-server /app/relay-server && \
      rm -rf bin relay-server.tar.gz; \
    fi

EXPOSE 36954
CMD ["./relay-server"]