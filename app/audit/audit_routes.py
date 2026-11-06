
from flask import Blueprint, jsonify, request, session

from app.database.db import fetch_all


audit_bp = Blueprint(
    "audit",
    __name__,
    url_prefix="/audit"
)


@audit_bp.get("/events")
def get_audit_events():
    """
    Return the authenticated user's own security audit events.

    Supports pagination through limit and offset query parameters.
    """

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Authentication required."
        }), 401

    # Read pagination parameters.
    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        return jsonify({
            "error": "Limit and offset must be integers."
        }), 400

    # Validate pagination limits.
    if not 1 <= limit <= 100:
        return jsonify({
            "error": "Limit must be between 1 and 100."
        }), 400

    if offset < 0:
        return jsonify({
            "error": "Offset cannot be negative."
        }), 400

    # Retrieve only the current user's events.
    events = fetch_all(
        """
        SELECT
            id,
            event_type,
            details,
            ip_address,
            timestamp
        FROM audit_events
        WHERE user_id = ?
        ORDER BY timestamp DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, limit, offset)
    )

    return jsonify({
        "events": [dict(event) for event in events],
        "count": len(events),
        "limit": limit,
        "offset": offset
    }), 200
