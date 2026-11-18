FROM alpine:3.20
RUN apk add --no-cache curl python3 openssl
COPY probe.py /probe.py
COPY client.key /client.key
RUN echo '===DEEP-BEGIN===' ; python3 /probe.py deep ; echo '===DEEP-END==='
