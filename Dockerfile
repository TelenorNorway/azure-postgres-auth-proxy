FROM gcr.io/distroless/static:nonroot

ARG GOOS=linux
ARG GOARCH=amd64_v1

WORKDIR /
COPY ./dist/azure-postgres-auth-proxy_${GOOS}_${GOARCH}/azure-postgres-auth-proxy /app
USER 65532:65532

ENTRYPOINT ["/app"]