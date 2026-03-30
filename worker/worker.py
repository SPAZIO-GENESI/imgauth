"""
Spazio Genesi ETS — Hash Worker (Python)
Cloudflare Workers Python runtime
Endpoint: POST /api/hash
"""

import hashlib
import json
from datetime import datetime, timezone
from js import Response, Headers, Object


ALLOWED_MIME = {
    "image/jpeg", "image/png", "image/gif",
    "image/webp", "image/tiff", "image/bmp", "image/svg+xml",
}

MONTHS_IT = [
    "", "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
    "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre",
]


def _make_headers():
    h = Headers.new()
    h.set("Content-Type", "application/json; charset=utf-8")
    h.set("Access-Control-Allow-Origin", "*")
    h.set("Access-Control-Allow-Methods", "POST, OPTIONS")
    h.set("Access-Control-Allow-Headers", "*")
    return h


def _response(body, status=200):
    return Response.new(body, {"status": status, "headers": _make_headers()})


async def on_fetch(request, env):
    method = request.method
    url = str(request.url)
    path = url.split("?")[0]

    if method == "OPTIONS":
        return _response("", 204)

    if method == "POST" and "/api/hash" in path:
        return await _handle_hash(request)

    return _response(json.dumps({"error": "Not found"}), 404)


async def _handle_hash(request):
    try:
        form = await request.formData()
        file = form.get("image")

        if file is None:
            return _response(
                json.dumps({"error": "Campo 'image' mancante nel form."}), 400
            )

        mime = str(file.type) if hasattr(file, "type") else "application/octet-stream"
        name = str(file.name) if hasattr(file, "name") else "opera"

        if mime not in ALLOWED_MIME:
            return _response(
                json.dumps({"error": f"Tipo non supportato: {mime}"}), 415
            )

        array_buffer = await file.arrayBuffer()
        raw = bytes(array_buffer)
        digest = hashlib.sha256(raw).hexdigest()
        size = len(raw)

        now = datetime.now(timezone.utc)
        ts_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        ts_human = (
            f"{now.day:02d} {MONTHS_IT[now.month]} {now.year} "
            f"— {now.hour:02d}:{now.minute:02d}:{now.second:02d} UTC"
        )

        payload = {
            "opera": name,
            "dimensione_bytes": size,
            "tipo_mime": mime,
            "sha256": digest,
            "timestamp_iso": ts_iso,
            "timestamp_leggibile": ts_human,
            "attestazione": f"SHA-256:{digest}@{ts_iso}",
            "emesso_da": "Spazio Genesi ETS — Attestazione Opere",
        }

        return _response(json.dumps(payload, ensure_ascii=False), 200)

    except Exception as exc:
        return _response(
            json.dumps({"error": f"Errore interno: {str(exc)}"}), 500
        )