# CertQR

Issues a client certificate and hands it over as a QR code. The QR code holds
`https://<host>/install#p12=<base64url PKCS#12>&n=<name>`. Browsers never send
the part after `#` to the server, so `/install` is just static HTML + JS that
turns the fragment into a `.p12` file on the device.

## Run

    python -m venv .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/python app.py            # listens on 0.0.0.0:5000

Open http://<your-ip>:5000/ , issue a certificate, and scan the QR code with a phone on the same network.
After installing, open https://<your-ip>:5443/verify on the phone to check it.

Environment variables:
- `CERTQR_PUBLIC_BASE_URL`: the base URL to put in the QR code (default: the host the request came in on)
- `CERTQR_CA_DIR`: where the CA key and certificate are kept (default `./ca`, created on first start)
- `CERTQR_VERIFY_PORT`: HTTPS port for the verify page, which asks for a client certificate (default 5443)
- `CERTQR_VERIFY_URL`: full verify URL to link to, if it differs from `https://<host>:<verify port>/verify`
- `CERTQR_SERVER_NAMES`: comma-separated names/IPs for the auto-generated server TLS certificate (default: localhost, hostname, LAN IP)
- `CERTQR_TLS_CERT`, `CERTQR_TLS_KEY`: use your own server TLS certificate instead
- `CERTQR_MAIN_TLS=1`: serve the main pages over HTTPS too (no client certificate asked)
- `HOST`, `PORT`

## Routes
- `GET /`: issue form
- `POST /issue`: creates key + certificate and returns the QR code (inline SVG) plus the P12 password
- `GET /install`, `GET /install.js`: static install page; CSP `connect-src 'none'`
- `GET /ca.crt`: the CA certificate (public)
- `GET /verify` (on the verify port): mutual TLS. Reports whether the client sent a certificate, whether it is
  issued by this CA, whether it is currently valid and allowed for client authentication, and its serial and
  fingerprint. Proof that the client holds the private key comes from the TLS handshake itself. A certificate from
  another CA is rejected during the handshake, so the browser shows a connection error instead of the page.
