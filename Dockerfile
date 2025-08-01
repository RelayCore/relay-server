FROM alpine:latest

ARG RELAY_VERSION=latest
WORKDIR /app

RUN apk add --no-cache curl tar \
    && if [ "$RELAY_VERSION" = "latest" ]; then \
         RELAY_VERSION=$(curl -s https://api.github.com/repos/RelayCore/relay-server/releases/latest | grep tag_name | cut -d '"' -f 4); \
       fi \
    && curl -L -o relay-server.tar.gz "https://github.com/RelayCore/relay-server/releases/download/${RELAY_VERSION}/relay-server_${RELAY_VERSION}_linux_amd64.zip" \
    && mkdir bin \
    && unzip relay-server.tar.gz -d bin \
    && mv bin/relay-server /app/relay-server \
    && rm -rf bin relay-server.tar.gz

COPY config.yaml .
COPY uploads/ ./uploads/
EXPOSE 36954
CMD ["./relay-server"]
