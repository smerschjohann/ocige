FROM gcr.io/distroless/static:nonroot

COPY ocige /usr/local/bin/ocige

ENTRYPOINT ["/usr/local/bin/ocige"]
