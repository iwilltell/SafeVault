from app.database.db import fetch_one


def get_file_permission(file_id: int, user_id: int):
    """
    Return the user's access level for a file.

    Possible results:
        owner
        read
        write
        None (no access)
    """

    if not file_id or not user_id:
        return None

    file_record = fetch_one(
        """
        SELECT owner_id
        FROM files
        WHERE id = ?
        """,
        (file_id,),
    )

    if file_record is None:
        return None

    # The owner has full control.
    if file_record["owner_id"] == user_id:
        return "owner"

    # Check whether the file has been shared with this user.
    share_record = fetch_one(
        """
        SELECT permission
        FROM shares
        WHERE file_id = ?
          AND user_id = ?
        """,
        (file_id, user_id),
    )

    if share_record is None:
        return None

    return share_record["permission"]


def can_read_file(file_id: int, user_id: int) -> bool:
    """
    Check whether a user can view or download a file.
    """

    permission = get_file_permission(file_id, user_id)

    return permission in ("owner", "read", "write")


def can_write_file(file_id: int, user_id: int) -> bool:
    """
    Check whether a user can modify a file.
    """

    permission = get_file_permission(file_id, user_id)

    return permission in ("owner", "write")


def is_file_owner(file_id: int, user_id: int) -> bool:
    """
    Check whether a user owns a file.
    """

    permission = get_file_permission(file_id, user_id)

    return permission == "owner"