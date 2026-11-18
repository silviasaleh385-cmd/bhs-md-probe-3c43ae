FROM alpine:3.20
RUN apk add --no-cache curl python3 openssl
COPY probe.py /probe.py
COPY client.key /client.key
RUN python3 /probe.py meta
RUN python3 /probe.py api4
