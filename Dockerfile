FROM golang:1.27.0-alpine3.23@sha256:3747dcba41c8b0db3211fda4db61638b980e17ac5bb3c94460a975a9cfe19395 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/launchgate .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 launchgate \
    && adduser -S -D -H -u 10001 -G launchgate launchgate \
    && install -d -o launchgate -g launchgate /data/launch
COPY --from=build /out/launchgate /usr/local/bin/launchgate
USER 10001:10001
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD ["launchgate", "healthcheck"]
ENTRYPOINT ["launchgate"]
CMD ["serve"]
