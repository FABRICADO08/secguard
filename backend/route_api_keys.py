"""Create, list and revoke scoped API keys (deployment administrators only)."""

from __future__ import annotations

from flask import jsonify, request

from backend.route_audit import actor
from backend.route_objectives import can_edit
from backend.security import api_keys

FORBIDDEN = ({"success": False, "error": "Managing API keys needs an administrator."}, 403)


def register_routes(app):
    @app.get("/api/keys")
    def list_api_keys():
        if not can_edit():
            return jsonify(FORBIDDEN[0]), FORBIDDEN[1]
        return jsonify({"success": True, "keys": api_keys.listing(), "scopes": list(api_keys.SCOPES)})

    @app.post("/api/keys")
    def create_api_key():
        if not can_edit():
            return jsonify(FORBIDDEN[0]), FORBIDDEN[1]
        name, scopes, days, error = api_keys.clean_request(request.get_json(silent=True) or {})
        if error:
            return jsonify({"success": False, "error": error}), 400
        record, token = api_keys.create(name, scopes, days, actor())
        return jsonify({"success": True, "key": record, "token": token}), 201

    @app.delete("/api/keys/<key_id>")
    def revoke_api_key(key_id: str):
        if not can_edit():
            return jsonify(FORBIDDEN[0]), FORBIDDEN[1]
        if not api_keys.revoke(key_id):
            return jsonify({"success": False, "error": "API key not found."}), 404
        return jsonify({"success": True, "id": key_id})
