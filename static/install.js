// Runs entirely in the browser. Reads the PKCS#12 from location.hash,
// never sends it anywhere (the page CSP also forbids network requests).
(function () {
  var p12 = null;
  var name = "certificate";
  var blobUrl = null;

  function $(id) { return document.getElementById(id); }

  function b64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function safeFileName(s) {
    return (s.replace(/[^A-Za-z0-9._-]/g, "_") || "certificate") + ".p12";
  }

  function getBlobUrl() {
    if (!blobUrl) {
      blobUrl = URL.createObjectURL(new Blob([p12], { type: "application/x-pkcs12" }));
    }
    return blobUrl;
  }

  function download() {
    var a = document.createElement("a");
    a.href = getBlobUrl();
    a.download = safeFileName(name);
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function install() {
    // Navigating to the file (no download attribute) lets the OS pick its
    // certificate installer where it supports that for application/x-pkcs12.
    window.location.href = getBlobUrl();
  }

  function wipe() {
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    blobUrl = null;
    if (p12) p12.fill(0);
    p12 = null;
    $("actions").hidden = true;
    $("status").textContent = "Certificate removed from this page.";
  }

  var params = new URLSearchParams(location.hash.slice(1));
  // Remove the secret from the address bar and the browser history entry.
  history.replaceState(null, "", location.pathname);

  try {
    if (!params.get("p12")) throw new Error("no certificate in link");
    p12 = b64urlToBytes(params.get("p12"));
    if (params.get("n")) name = new TextDecoder().decode(b64urlToBytes(params.get("n")));
  } catch (e) {
    $("status").textContent = "No certificate found in this link. Scan the QR code again.";
    return;
  }

  $("name").textContent = name;
  $("size").textContent = String(p12.length);
  $("status").textContent = "Certificate ready.";
  $("actions").hidden = false;
  $("download").addEventListener("click", download);
  $("install").addEventListener("click", install);
  $("wipe").addEventListener("click", wipe);
})();
