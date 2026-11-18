FROM alpine:3.20
RUN apk add --no-cache curl python3
COPY probe.py /probe.py
RUN python3 /probe.py meta
RUN python3 /probe.py api
