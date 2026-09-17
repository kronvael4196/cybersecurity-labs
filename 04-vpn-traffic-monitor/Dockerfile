FROM python:3.12-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables tcpdump tshark curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY vpn.py analyze.py ./
