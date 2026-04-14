FROM gcr.io/distroless/static:nonroot

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/ocige /usr/local/bin/ocige

ENTRYPOINT ["/usr/local/bin/ocige"]
