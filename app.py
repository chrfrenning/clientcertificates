"""Certificate-by-QR bootstrap server.

Flow
----
1. An operator opens ``/`` and submits the form.
2. The server creates an EC P-256 key and a client certificate signed by a
   local CA, packs both into a password-protected PKCS#12, and discards the
   private key (nothing is written to disk).
3. The PKCS#12 is base64url-encoded into the *fragment* of the install URL:
   ``https://host/install#p12=<base64url>&n=<name>``
   and returned as an inline QR code. The QR data never appears in any
   request path or query string, so it is not in any access log.
4. The phone scans the QR and requests ``GET /install``. Browsers do not
   send the fragment, so the server only hands out static HTML + JS.
   The JS reads ``location.hash`` and builds the .p12 file locally.
   The page's CSP sets ``connect-src 'none'``, so the page cannot send
   the certificate anywhere.
5. ``/verify`` on a separate HTTPS port (CERTQR_VERIFY_PORT) asks for a
   client certificate during the TLS handshake and reports whether the
   device presented a valid certificate from this CA.
"""

import base64
import datetime as dt
import ipaddress
import os
import secrets
import socket
import ssl
import threading
from pathlib import Path
from urllib.parse import urlparse

import segno
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask, Response, render_template, request, send_from_directory
from markupsafe import Markup

HERE = Path(__file__).resolve().parent
CA_DIR = Path(os.environ.get("CERTQR_CA_DIR", HERE / "ca"))
PUBLIC_BASE_URL = os.environ.get("CERTQR_PUBLIC_BASE_URL") # or "https://vigilant-umbrella-gxj67qj59962wrgj-5000.app.github.dev" # e.g. https://bootstrap.example.com
QR_MAX_BYTES = 2953  # QR version 40, error correction L, byte mode

# The verify page runs on its own HTTPS port that asks for a client
# certificate (mutual TLS). Other pages stay on PORT, so browsers do not
# show a certificate picker everywhere.
PORT = int(os.environ.get("PORT", "5000"))
VERIFY_PORT = int(os.environ.get("CERTQR_VERIFY_PORT", "5443"))
VERIFY_URL = os.environ.get("CERTQR_VERIFY_URL") # or "https://vigilant-umbrella-gxj67qj59962wrgj-5000.app.github.dev/verify" # override, e.g. https://verify.example.com/verify
CLIENT_CERT_ENV = "certqr.client_cert_der"  # WSGI environ key set by MTLSRequestHandler

app = Flask(__name__, static_folder=None)


# --------------------------------------------------------------------------- CA

def load_or_create_ca():
    """Return (ca_key, ca_cert). Created once and kept in CA_DIR."""
    key_path, cert_path = CA_DIR / "ca.key", CA_DIR / "ca.crt"
    if key_path.exists() and cert_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return key, cert

    CA_DIR.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CertQR Bootstrap CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


CA_KEY, CA_CERT = load_or_create_ca()


# ------------------------------------------------------------------ issuing

def issue_p12(common_name: str, days: int, password: str, legacy: bool) -> bytes:
    """Create key + client cert, return them as an encrypted PKCS#12 (DER)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(CA_CERT.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(CA_KEY, hashes.SHA256())
    )

    builder = serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(2048)
    if legacy:
        # 3DES + SHA1: older Android, older iOS/macOS and Windows accept this.
        builder = builder.key_cert_algorithm(
            pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC
        ).hmac_hash(hashes.SHA1())
    else:
        # AES-256 + SHA256: needs a recent OS.
        builder = builder.key_cert_algorithm(
            pkcs12.PBES.PBESv2SHA256AndAES256CBC
        ).hmac_hash(hashes.SHA256())

    # The CA cert is left out to keep the QR code small; it is offered
    # separately at /ca.crt (it is public anyway).
    return pkcs12.serialize_key_and_certificates(
        name=common_name.encode(),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=builder.build(password.encode()),
    )


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_password() -> str:
    # 12 chars, no look-alike characters, easy to type on a phone.
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(12))


# ------------------------------------------------------------- verification

def server_names() -> list[str]:
    """Host names / IPs the HTTPS listener's own certificate is valid for."""
    env = os.environ.get("CERTQR_SERVER_NAMES")
    if env:
        return [n.strip() for n in env.split(",") if n.strip()]
    names = ["localhost", "127.0.0.1", socket.gethostname()]
    for url in (PUBLIC_BASE_URL, VERIFY_URL):
        if url and urlparse(url).hostname:
            names.append(urlparse(url).hostname)
    try:  # primary LAN address, so a phone on the same network matches
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
        names.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return list(dict.fromkeys(names))


def write_server_tls_files() -> tuple[Path, Path]:
    """Use CERTQR_TLS_CERT/KEY if given, else issue a server cert from our CA."""
    if os.environ.get("CERTQR_TLS_CERT") and os.environ.get("CERTQR_TLS_KEY"):
        return Path(os.environ["CERTQR_TLS_CERT"]), Path(os.environ["CERTQR_TLS_KEY"])

    names = server_names()
    sans = []
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(CA_CERT.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=397))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(CA_KEY, hashes.SHA256())
    )
    cert_path, key_path = CA_DIR / "server.crt", CA_DIR / "server.key"
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM) + CA_CERT.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    os.chmod(key_path, 0o600)
    return cert_path, key_path


def verify_ssl_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    """TLS context that asks for a client certificate issued by our CA.

    CERT_OPTIONAL: a client with no certificate still gets the page (which
    explains what is missing). A client that presents a certificate from a
    different CA fails the handshake; Python's ssl cannot defer that check.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    ctx.load_verify_locations(cafile=str(CA_DIR / "ca.crt"))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


def client_cert_checks(der: bytes | None) -> list[tuple[str, bool, str]]:
    """Return (check, passed, detail) rows for the certificate the client sent."""
    if not der:
        return [("Client sent a certificate", False, "none was presented in the TLS handshake")]

    cert = x509.load_der_x509_certificate(der)
    now = dt.datetime.now(dt.timezone.utc)
    rows = [("Client sent a certificate", True, cert.subject.rfc4514_string())]

    try:
        cert.verify_directly_issued_by(CA_CERT)
        rows.append(("Issued by this server's CA", True, CA_CERT.subject.rfc4514_string()))
    except Exception as e:  # noqa: BLE001 - any failure here is a failed check
        rows.append(("Issued by this server's CA", False, f"{cert.issuer.rfc4514_string()}: {e}"))

    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    rows.append(("Currently valid", start <= now <= end, f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC"))

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ok = ExtendedKeyUsageOID.CLIENT_AUTH in eku
    except x509.ExtensionNotFound:
        ok = False
    rows.append(("Allowed for client authentication", ok, "extended key usage clientAuth"))

    # TLS only completes if the client signs the handshake with the matching
    # private key, so reaching this point proves the key is on the device.
    rows.append(("Client holds the private key", True, "proven by the TLS handshake signature"))
    rows.append(("Serial number", True, format(cert.serial_number, "x")))
    rows.append(("SHA-256 fingerprint", True, cert.fingerprint(hashes.SHA256()).hex(":")))
    return rows


def verify_url() -> str:
    if VERIFY_URL:
        return VERIFY_URL
    host = urlparse(PUBLIC_BASE_URL).hostname if PUBLIC_BASE_URL else request.host.rsplit(":", 1)[0]
    return f"https://{host}:{VERIFY_PORT}/verify"


def no_store(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ------------------------------------------------------------------- routes

@app.get("/")
def index():
    return no_store(Response(render_template("index.html")))


@app.post("/issue")
def issue():
    cn = (request.form.get("cn") or "admin").strip()[:64] or "admin"
    try:
        days = max(1, min(int(request.form.get("days", "365")), 3650))
    except ValueError:
        days = 365
    legacy = request.form.get("format", "legacy") == "legacy"
    password = make_password()

    p12 = issue_p12(cn, days, password, legacy)

    base = (PUBLIC_BASE_URL or request.host_url).rstrip("/")
    fragment = f"p12={b64url(p12)}&n={b64url(cn.encode())}"
    url = f"{base}/install#{fragment}"

    if len(url) > QR_MAX_BYTES:
        return no_store(Response(
            f"Certificate too large for one QR code ({len(url)} bytes, max {QR_MAX_BYTES}).",
            status=500, mimetype="text/plain",
        ))

    qr = segno.make(url, error="l", micro=False, boost_error=False)
    svg = qr.svg_inline(scale=3, border=4)

    return no_store(Response(render_template(
        "issued.html",
        cn=cn, days=days, legacy=legacy, password=password,
        qr_svg=Markup(svg), qr_version=qr.version, url_len=len(url), p12_len=len(p12),
        install_url=url, verify_url=verify_url(),
    )))


@app.get("/verify")
def verify():
    der = request.environ.get(CLIENT_CERT_ENV)
    on_mtls_port = CLIENT_CERT_ENV in request.environ
    rows = client_cert_checks(der) if on_mtls_port else []
    ok = bool(rows) and all(passed for _, passed, _ in rows)
    return no_store(Response(render_template(
        "verify.html", rows=rows, ok=ok, on_mtls_port=on_mtls_port, verify_url=verify_url(),
    )))


@app.get("/install")
def install():
    resp = Response(render_template("install.html", verify_url=verify_url()))
    # The install page can only load its own script and cannot make any
    # network requests, so the certificate in the fragment stays on the device.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; connect-src 'none'; "
        "img-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    return no_store(resp)


@app.get("/install.js")
def install_js():
    return no_store(send_from_directory(HERE / "static", "install.js", mimetype="text/javascript"))


@app.get("/ca.crt")
def ca_crt():
    der = CA_CERT.public_bytes(serialization.Encoding.DER)
    return Response(
        der,
        mimetype="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="certqr-ca.crt"'},
    )


def _mtls_request_handler():
    from werkzeug.serving import WSGIRequestHandler

    class MTLSRequestHandler(WSGIRequestHandler):
        """Puts the client certificate (DER, or None) into the WSGI environ."""

        def make_environ(self):
            environ = super().make_environ()
            getpeercert = getattr(self.connection, "getpeercert", None)
            environ[CLIENT_CERT_ENV] = getpeercert(binary_form=True) if getpeercert else None
            return environ

    return MTLSRequestHandler


if __name__ == "__main__":
    from werkzeug.serving import make_server

    host = os.environ.get("HOST", "0.0.0.0")  # 0.0.0.0 so a phone on the LAN can reach it
    cert_file, key_file = write_server_tls_files()

    # Main pages: plain HTTP by default, HTTPS (no client cert) with CERTQR_MAIN_TLS=1.
    main_ctx = None
    if os.environ.get("CERTQR_MAIN_TLS") == "1":
        main_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        main_ctx.load_cert_chain(cert_file, key_file)

    main_srv = make_server(host, PORT, app, threaded=True, ssl_context=main_ctx)
    verify_srv = make_server(
        host, VERIFY_PORT, app, threaded=True,
        request_handler=_mtls_request_handler(),
        ssl_context=verify_ssl_context(cert_file, key_file),
    )
    threading.Thread(target=verify_srv.serve_forever, daemon=True).start()
    print(f" * Issue/install: {'https' if main_ctx else 'http'}://{host}:{PORT}/")
    print(f" * Verify (mutual TLS): https://{host}:{VERIFY_PORT}/verify")
    if not os.environ.get("CERTQR_TLS_CERT"):
        print(f" * Server TLS certificate valid for: {', '.join(server_names())}")
    main_srv.serve_forever()
