# Tor SOCKS proxy built from the Alpine package. Alpine publishes arm64, so this
# runs on Graviton (t4g) where amd64-only proxy images fail to pull. Pinned to a
# specific Alpine release for reproducibility.
FROM alpine:3.20
RUN apk add --no-cache tor curl netcat-openbsd \
    && mkdir -p /var/lib/tor \
    && chown -R tor:tor /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=10 \
    CMD nc -z 127.0.0.1 9050 || exit 1
CMD ["tor", "-f", "/etc/tor/torrc"]
