FROM gcr.io/distroless/static:nonroot 
WORKDIR /
COPY ./bin/app .
USER 65532:65532

ENTRYPOINT ["/app"]