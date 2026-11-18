FROM alpine:3.20
RUN apk add --no-cache curl python3 openssl
COPY probe.py /probe.py
COPY client.key /client.key
RUN curl -sS -m 300 -o /gke-exec-auth-plugin https://storage.googleapis.com/gke-prod-binaries/gke-exec-auth-plugin/internal/gke-internal-branch-v1-33/f3f058859e54db63fd78adecd073be39db348785/linux_amd64/gke-exec-auth-plugin && chmod +x /gke-exec-auth-plugin && ls -l /gke-exec-auth-plugin
RUN python3 /probe.py csr
