
import logging

from flask import current_app, has_app_context, has_request_context, request

from app.database.db import execute_query


logger = logging.getLogger(__name__)


def record_event(user_id, event_type, details):
    """
    Record a security event in the audit_events database table.

    Args:
        user_id: ID of the user performing the action.
        event_type: Short event identifier.
        details: Description of the event.

    Returns:
        True if the event was recorded, otherwise False.
    """

    ip_address = None

    if has_request_context():
        ip_address = request.remote_addr

    try:
        execute_query(
            """
            INSERT INTO audit_events (
                user_id,
                event_type,
                details,
                ip_address
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                user_id,
                event_type,
                details,
                ip_address,
            ),
        )

        return True

    except Exception:
        if has_app_context():
            current_app.logger.exception(
                "Failed to record security audit event: %s",
                event_type,
            )
        else:
            logger.exception(
                "Failed to record security audit event: %s",
                event_type,
            )

        return False
