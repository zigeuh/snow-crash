FROM debian:latest

RUN apt update && \
    apt install -y john && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

COPY password /

ENTRYPOINT ["john"]
