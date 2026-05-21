FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends tor netcat-openbsd ca-certificates && \
    mkdir -p /var/lib/tor /var/log/tor && \
    chown -R debian-tor:debian-tor /var/lib/tor /var/log/tor && \
    rm -rf /var/lib/apt/lists/*

COPY docker/tor/torrc /etc/tor/torrc

EXPOSE 9050

USER debian-tor

CMD ["tor", "-f", "/etc/tor/torrc"]
