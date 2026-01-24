FROM debian:latest

RUN apt update && \
    apt install -y tshark && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

COPY level02.pcap /

ENTRYPOINT ["tshark"]
