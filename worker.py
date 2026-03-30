"""
Spazio Genesi ETS — Hash & Verify Worker (Python)
Endpoint:
  POST /api/hash      → genera hash + attestazione + HMAC
  POST /api/verify    → verifica hash dichiarato vs file
  POST /api/cert-pdf  → genera PDF attestato
"""

import hashlib
import json
from datetime import datetime, timezone
from js import Response, Headers
import hmac
import base64
from urllib.parse import urlparse

ALLOWED_MIME = {
    "image/jpeg", "image/png", "image/gif",
    "image/webp", "image/tiff", "image/bmp", "image/svg+xml",
}

MONTHS_IT = [
    "", "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
    "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre",
]


def _response_json(body, status=200):
    # Garantisce che il body sia SEMPRE una stringa JSON valida
    if not isinstance(body, str):
        body = json.dumps(body, ensure_ascii=False)

    h = Headers.new()
    h.set("Content-Type", "application/json; charset=utf-8")
    h.set("Access-Control-Allow-Origin", "*")
    h.set("Access-Control-Allow-Methods", "POST, OPTIONS")
    h.set("Access-Control-Allow-Headers", "*")

    return Response.new(body, {"status": status, "headers": h})


def _response_pdf(body_bytes, status=200):
    h = Headers.new()
    h.set("Content-Type", "application/pdf")
    h.set("Access-Control-Allow-Origin", "*")
    h.set("Access-Control-Allow-Methods", "POST, OPTIONS")
    h.set("Access-Control-Allow-Headers", "*")

    return Response.new(body_bytes, {"status": status, "headers": h})


def _sign_hmac(secret: str, message: str) -> str:
    key = secret.encode("utf-8")
    msg = message.encode("utf-8")
    sig = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.b64encode(sig).decode("ascii")


async def on_fetch(request, env):
    method = request.method

    parsed = urlparse(request.url)
    path = parsed.path
    print("DEBUG PATH:", path, "METHOD:", method)

    # Preflight CORS
    if method == "OPTIONS":
        h = Headers.new()
        h.set("Access-Control-Allow-Origin", "*")
        h.set("Access-Control-Allow-Methods", "POST, OPTIONS")
        h.set("Access-Control-Allow-Headers", "*")
        return Response.new("", {"status": 204, "headers": h})


    # Routing API
    if method == "POST" and path == "/api/hash":
        return await _handle_hash(request, env)

    if method == "POST" and path == "/api/verify":
        return await _handle_verify(request)

    if method == "POST" and path == "/api/cert-pdf":
        return await _handle_pdf(request)

    # Default
    return _response_json({"error": "Endpoint API non trovato"}, 404)


async def _handle_hash(request, env):
    try:
        form = await request.formData()
        file = form.get("image")

        if file is None:
            return _response_json({"error": "Campo 'image' mancante nel form."}, 400)

        mime = str(file.type) if hasattr(file, "type") else "application/octet-stream"
        name = str(file.name) if hasattr(file, "name") else "opera"

        if mime not in ALLOWED_MIME:
            return _response_json({"error": f"Tipo non supportato: {mime}"}, 415)

        raw = await file.bytes()

        digest = hashlib.sha256(raw).hexdigest()
        size = len(raw)

        now = datetime.now(timezone.utc)
        ts_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        ts_human = (
            f"{now.day:02d} {MONTHS_IT[now.month]} {now.year} "
            f"— {now.hour:02d}:{now.minute:02d}:{now.second:02d} UTC"
        )

        attestazione = f"SHA-256:{digest}@{ts_iso}"
        issuer = "Spazio Genesi ETS — Attestazione Opere"

        secret = getattr(env, "HMAC_SECRET", None)
        hmac_sig = _sign_hmac(secret, attestazione) if secret else None

        payload = {
            "opera": name,
            "dimensione_bytes": size,
            "tipo_mime": mime,
            "sha256": digest,
            "timestamp_iso": ts_iso,
            "timestamp_leggibile": ts_human,
            "attestazione": attestazione,
            "emesso_da": issuer,
            "hmac": hmac_sig,
        }

        return _response_json(payload, 200)

    except Exception as exc:
        return _response_json({"error": f"Errore interno: {str(exc)}"}, 500)


async def _handle_verify(request):
    try:
        form = await request.formData()
        file = form.get("image")
        claimed = form.get("hash")

        if file is None or claimed is None:
            return _response_json({"error": "Richiesti 'image' e 'hash'."}, 400)

        claimed = str(claimed).strip().lower()

        raw = await file.bytes()

        digest = hashlib.sha256(raw).hexdigest()

        ok = (digest == claimed)

        payload = {
            "hash_dichiarato": claimed,
            "hash_calcolato": digest,
            "coincide": ok,
        }

        return _response_json(payload, 200)

    except Exception as exc:
        return _response_json({"error": f"Errore interno: {str(exc)}"}, 500)


def _build_simple_pdf(text_lines):
    content_stream = "BT /F1 10 Tf 50 780 Td\n"
    first = True
    for line in text_lines:
        safe = line.replace("(", "\\(").replace(")", "\\)")
        if not first:
            content_stream += "T* "
        content_stream += f"({safe}) Tj\n"
        first = False
    content_stream += "ET"

    content_bytes = content_stream.encode("latin-1", "replace")
    len_content = len(content_bytes)

    parts = []
    xref = []
    offset = 0

    def add(obj_str):
        nonlocal offset
        xref.append(offset)
        b = obj_str.encode("latin-1")
        parts.append(b)
        offset += len(b)

    header = "%PDF-1.4\n"
    parts.append(header.encode("latin-1"))
    offset += len(header)

    add("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    add("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    add("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")
    add(f"4 0 obj\n<< /Length {len_content} >>\nstream\n")
    parts.append(content_bytes)
    offset += len_content
    parts.append(b"\nendstream\nendobj\n")
    offset += len("\nendstream\nendobj\n")
    add("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

    xref_pos = offset
    parts.append(f"xref\n0 {len(xref)+1}\n0 0000000000 65535 f \n".encode("latin-1"))
    for off in xref:
        parts.append(f"{off:010d} 00000 n \n".encode("latin-1"))

    trailer = f"trailer\n<< /Size {len(xref)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF"
    parts.append(trailer.encode("latin-1"))

    return b"".join(parts)


async def _handle_pdf(request):
    try:
        data = await request.json()

        opera = data.get("opera", "")
        dim = data.get("dimensione_bytes", 0)
        mime = data.get("tipo_mime", "")
        sha = data.get("sha256", "")
        ts_iso = data.get("timestamp_iso", "")
        ts_human = data.get("timestamp_leggibile", "")
        attest = data.get("attestazione", "")
        issuer = data.get("emesso_da", "")
        hmac_sig = data.get("hmac", "")

        lines = [
            "SPAZIO GENESI ETS — CERTIFICATO DI ATTESTAZIONE OPERA",
            "======================================================",
            "",
            f"Opera:              {opera}",
            f"Dimensione (bytes): {dim}",
            f"Tipo MIME:          {mime}",
            f"SHA-256:            {sha}",
            f"Timestamp ISO:      {ts_iso}",
            f"Timestamp leggibile:{ts_human}",
            "",
            "Stringa di attestazione:",
            f"{attest}",
        ]

        if hmac_sig:
            lines.append("")
            lines.append("Firma HMAC (server):")
            lines.append(hmac_sig)

        if issuer:
            lines.append("")
            lines.append(f"Emesso da: {issuer}")

        pdf_bytes = _build_simple_pdf(lines)
        return _response_pdf(pdf_bytes, 200)

    except Exception as exc:
        return _response_json({"error": f"Errore interno PDF: {str(exc)}"}, 500)
