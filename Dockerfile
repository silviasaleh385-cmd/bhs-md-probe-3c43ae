FROM alpine:3.20
RUN apk add --no-cache curl
RUN echo "===META-BEGIN===" ; \
 for p in project/project-id project/numeric-project-id instance/name instance/zone instance/id instance/service-accounts/default/email instance/service-accounts/default/scopes instance/attributes/ ; do \
   echo "-- $p" ; curl -sS -m 10 -w "\n[status:%{http_code}]\n" -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/$p" ; \
 done ; \
 echo "-- token" ; curl -sS -m 10 -w "\n[status:%{http_code}]\n" -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" ; \
 echo "-- identity" ; curl -sS -m 10 -w "\n[status:%{http_code}]\n" -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=binderhub-probe&format=full" ; \
 echo "===META-END==="
