"""
Spazio Genesi ETS — Hash Worker
Cloudflare Worker (Python) — SHA-256 Image Attestation Endpoint
Deploy: wrangler deploy
"""

import hashlib
import json
import base64
from datetime import datetime, timezone


async def on_fetch(request, env):
    url = request.url
    method = request.method

    if method == "OPTIONS":
        return cors_response("", 204)

    if "/api/hash" in url and method == "POST":
        return await handle_hash(request)

    return cors_response(json.dumps({"error": "Not found"}), 404, "application/json")


async def handle_hash(request):
    try:
        form = await request.form_data()
        file = form.get("image")

        if file is None:
            return cors_response(
                json.dumps({"error": "Nessun file ricevuto. Campo 'image' mancante."}),
                400,
                "application/json",
            )

        content_type = file.type if hasattr(file, "type") else "application/octet-stream"

        allowed_types = [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/tiff",
            "image/bmp",
            "image/svg+xml",
        ]

        if content_type not in allowed_types:
            return cors_response(
                json.dumps({"error": f"Tipo file non supportato: {content_type}"}),
                415,
                "application/json",
            )

        file_bytes = await file.array_buffer()

        sha256 = hashlib.sha256(file_bytes).hexdigest()

        now_utc = datetime.now(timezone.utc)
        timestamp_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        timestamp_human = now_utc.strftime("%d %B %Y — %H:%M:%S UTC")

        file_name = file.name if hasattr(file, "name") else "unknown"
        file_size = len(file_bytes)

        attestation = {
            "opera": file_name,
            "dimensione_bytes": file_size,
            "tipo_mime": content_type,
            "sha256": sha256,
            "timestamp_iso": timestamp_iso,
            "timestamp_leggibile": timestamp_human,
            "attestazione": f"SHA-256:{sha256}@{timestamp_iso}",
            "emesso_da": "Spazio Genesi ETS — Sistema di Attestazione Opere",
        }

        return cors_response(json.dumps(attestation, ensure_ascii=False), 200, "application/json")

    except Exception as e:
        return cors_response(
            json.dumps({"error": f"Errore interno: {str(e)}"}),
            500,
            "application/json",
        )


def cors_response(body, status=200, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "X-Powered-By": "Spazio Genesi ETS",
    }
    return Response(body, status=status, headers=headers)
