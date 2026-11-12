"""Appwrite Cloud Functions Python entrypoint."""
from __future__ import annotations

import json
from .status import get_status, render_page

_HEADERS = {"content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff"}

def main(context):
    """Handle Appwrite context requests without logging or inspecting request data."""
    req = context.req
    method = getattr(req, "method", "")
    path = getattr(req, "path", "")
    if method != "GET":
        return context.res.text("Method Not Allowed\n", 405, {**_HEADERS, "allow": "GET"})
    if path == "/":
        return context.res.text(render_page(get_status()), 200, {**_HEADERS, "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})
    if path == "/api/status":
        body = json.dumps(get_status(), ensure_ascii=False, separators=(",", ":"))
        return context.res.text(body, 200, {**_HEADERS, "content-type": "application/json; charset=utf-8"})
    if path == "/healthz":
        return context.res.text("ok\n", 200, _HEADERS)
    return context.res.text("Not Found\n", 404, _HEADERS)
