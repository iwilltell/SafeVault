import hashlib
import mimetypes
import uuid

from io import BytesIO
from pathlib import Path

from flask import (
    Blueprint,
    jsonify,
    request,
    session,
    current_app,
    send_file,
)

from werkzeug.utils import secure_filename

from app.database.db import execute_query, fetch_one, fetch_all
from app.files.encryption import (
    encrypt_file,
    decrypt_file,
    EncryptionError,
)
from app.files.permissions import (
    get_file_permission,
    can_write_file,
    is_file_owner,
)


files_bp = Blueprint("files", __name__, url_prefix="/files")


ALLOWED_EXTENSIONS = {
    ".txt",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".csv",
    ".docx",
    ".xlsx",
}


def get_current_user_id():
    return session.get("user_id")


def get_file_access(file_id, user_id):
    """
    Return a file if the user owns it or has shared access.
    """

    return fetch_one(
        """
        SELECT f.*
        FROM files AS f
        WHERE f.id = ?
          AND (
              f.owner_id = ?
              OR EXISTS (
                  SELECT 1
                  FROM shares AS s
                  WHERE s.file_id = f.id
                    AND s.user_id = ?
                    AND s.permission IN ('read', 'write')
              )
          )
        """,
        (file_id, user_id, user_id),
    )


def get_storage_file(stored_name):
    """
    Resolve a stored filename inside the configured storage directory.
    """

    storage_path = Path(
        current_app.config["STORAGE_PATH"]
    ).resolve()

    if Path(stored_name).name != stored_name:
        return None

    file_path = (storage_path / stored_name).resolve()

    if file_path.parent != storage_path:
        return None

    return file_path


def read_original_content(file_record):
    """
    Read and decrypt a stored file, then verify its integrity.
    """

    file_path = get_storage_file(file_record["stored_name"])

    if file_path is None:
        raise OSError("Invalid stored filename")

    if not file_path.is_file():
        raise FileNotFoundError("Stored file does not exist")

    stored_content = file_path.read_bytes()

    if file_record["is_encrypted"]:
        original_content = decrypt_file(stored_content)
    else:
        original_content = stored_content

    actual_hash = hashlib.sha256(
        original_content
    ).hexdigest()

    if actual_hash != file_record["sha256_hash"]:
        raise ValueError("File integrity verification failed")

    return original_content


@files_bp.post("/upload")
def upload_file():

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return jsonify({"error": "No file provided"}), 400

    if not uploaded_file.filename:
        return jsonify({"error": "Filename is required"}), 400

    original_name = secure_filename(uploaded_file.filename)

    if not original_name:
        return jsonify({"error": "Invalid filename"}), 400

    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "File type not allowed"}), 400

    max_size = current_app.config["MAX_CONTENT_LENGTH"]
    file_content = uploaded_file.stream.read(max_size + 1)

    if not file_content:
        return jsonify({"error": "Empty files are not allowed"}), 400

    if len(file_content) > max_size:
        return jsonify({"error": "File is too large"}), 413

    sha256_hash = hashlib.sha256(file_content).hexdigest()

    try:
        encrypted_content = encrypt_file(file_content)
    except EncryptionError:
        current_app.logger.exception("File encryption failed")
        return jsonify({"error": "File encryption failed"}), 500

    stored_name = f"{uuid.uuid4().hex}{extension}"

    storage_path = Path(current_app.config["STORAGE_PATH"])
    storage_path.mkdir(parents=True, exist_ok=True)

    destination = storage_path / stored_name

    mime_type = mimetypes.guess_type(original_name)[0]
    mime_type = mime_type or "application/octet-stream"

    try:
        with destination.open("xb") as file:
            file.write(encrypted_content)

        execute_query(
            """
            INSERT INTO files (
                owner_id,
                original_name,
                stored_name,
                file_size,
                mime_type,
                sha256_hash,
                is_encrypted
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                original_name,
                stored_name,
                len(file_content),
                mime_type,
                sha256_hash,
                1,
            ),
        )

        saved_file = fetch_one(
            "SELECT id FROM files WHERE stored_name = ?",
            (stored_name,),
        )

        return jsonify({
            "message": "File uploaded and encrypted successfully",
            "file_id": saved_file["id"],
            "original_name": original_name,
            "stored_name": stored_name,
            "file_size": len(file_content),
            "encrypted_size": len(encrypted_content),
            "mime_type": mime_type,
            "sha256_hash": sha256_hash,
            "is_encrypted": True,
        }), 201

    except Exception:
        destination.unlink(missing_ok=True)
        current_app.logger.exception("Encrypted file upload failed")

        return jsonify({"error": "File upload failed"}), 500


@files_bp.get("")
def list_files():

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    files = fetch_all(
        """
        SELECT
            f.id,
            f.owner_id,
            f.original_name,
            f.file_size,
            f.mime_type,
            f.sha256_hash,
            f.is_encrypted,
            f.created_at,
            CASE
                WHEN f.owner_id = ? THEN 'owner'
                ELSE s.permission
            END AS access_type
        FROM files AS f
        LEFT JOIN shares AS s
            ON s.file_id = f.id
            AND s.user_id = ?
        WHERE f.owner_id = ?
           OR s.user_id = ?
        ORDER BY f.created_at DESC
        """,
        (user_id, user_id, user_id, user_id),
    )

    return jsonify({
        "files": [dict(file) for file in files],
        "count": len(files),
    }), 200


@files_bp.get("/<int:file_id>/download")
def download_file(file_id):

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    file_record = get_file_access(file_id, user_id)

    if file_record is None:
        return jsonify({"error": "File not found"}), 404

    try:
        original_content = read_original_content(file_record)

        return send_file(
            BytesIO(original_content),
            mimetype=file_record["mime_type"],
            as_attachment=True,
            download_name=file_record["original_name"],
        )

    except EncryptionError:
        current_app.logger.exception(
            "File decryption failed for file ID %s",
            file_id,
        )
        return jsonify({"error": "Unable to decrypt file"}), 500

    except ValueError:
        return jsonify({
            "error": "File integrity verification failed"
        }), 409

    except FileNotFoundError:
        return jsonify({"error": "Stored file is missing"}), 404

    except OSError:
        current_app.logger.exception(
            "File read failed for file ID %s",
            file_id,
        )
        return jsonify({"error": "Unable to read stored file"}), 500


@files_bp.post("/<int:file_id>/share")
def share_file(file_id):

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    if not is_file_owner(file_id, user_id):
        return jsonify({"error": "Only the file owner can share it"}), 403

    data = request.get_json(silent=True) or {}

    target_username = data.get("username")
    permission = data.get("permission")

    if not isinstance(target_username, str) or not target_username.strip():
        return jsonify({"error": "A target username is required"}), 400

    target_username = target_username.strip()

    if permission not in ("read", "write"):
        return jsonify({"error": "Permission must be read or write"}), 400

    target_user = fetch_one(
        "SELECT id FROM users WHERE username = ?",
        (target_username,),
    )

    if target_user is None:
        return jsonify({"error": "Target user not found"}), 404

    target_user_id = target_user["id"]

    if target_user_id == user_id:
        return jsonify({"error": "You already own this file"}), 400

    try:
        existing_share = fetch_one(
            """
            SELECT id
            FROM shares
            WHERE file_id = ? AND user_id = ?
            """,
            (file_id, target_user_id),
        )

        if existing_share:
            execute_query(
                """
                UPDATE shares
                SET permission = ?, shared_by_id = ?
                WHERE file_id = ? AND user_id = ?
                """,
                (
                    permission,
                    user_id,
                    file_id,
                    target_user_id,
                ),
            )
            message = "Existing sharing permission updated"
        else:
            execute_query(
                """
                INSERT INTO shares (
                    file_id,
                    user_id,
                    shared_by_id,
                    permission
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    file_id,
                    target_user_id,
                    user_id,
                    permission,
                ),
            )
            message = "File shared successfully"

        return jsonify({
            "message": message,
            "file_id": file_id,
            "username": target_username,
            "permission": permission,
        }), 200

    except Exception:
        current_app.logger.exception("File sharing failed")
        return jsonify({"error": "Unable to share file"}), 500


@files_bp.get("/<int:file_id>/shares")
def list_shares(file_id):

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    if not is_file_owner(file_id, user_id):
        return jsonify({"error": "Only the file owner can view shares"}), 403

    shares = fetch_all(
        """
        SELECT
            s.user_id,
            u.username,
            u.email,
            s.permission,
            s.created_at
        FROM shares AS s
        JOIN users AS u ON u.id = s.user_id
        WHERE s.file_id = ?
        ORDER BY s.created_at DESC
        """,
        (file_id,),
    )

    return jsonify({
        "file_id": file_id,
        "shares": [dict(share) for share in shares],
        "count": len(shares),
    }), 200


@files_bp.put("/<int:file_id>/share/<int:target_user_id>")
def update_share_permission(file_id, target_user_id):

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    if not is_file_owner(file_id, user_id):
        return jsonify({"error": "Only the file owner can change permissions"}), 403

    data = request.get_json(silent=True) or {}
    permission = data.get("permission")

    if permission not in ("read", "write"):
        return jsonify({"error": "Permission must be read or write"}), 400

    existing_share = fetch_one(
        """
        SELECT id
        FROM shares
        WHERE file_id = ? AND user_id = ?
        """,
        (file_id, target_user_id),
    )

    if existing_share is None:
        return jsonify({"error": "Share not found"}), 404

    execute_query(
        """
        UPDATE shares
        SET permission = ?, shared_by_id = ?
        WHERE file_id = ? AND user_id = ?
        """,
        (
            permission,
            user_id,
            file_id,
            target_user_id,
        ),
    )

    return jsonify({
        "message": "Sharing permission updated",
        "file_id": file_id,
        "user_id": target_user_id,
        "permission": permission,
    }), 200


@files_bp.delete("/<int:file_id>/share/<int:target_user_id>")
def revoke_share(file_id, target_user_id):

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    if not is_file_owner(file_id, user_id):
        return jsonify({"error": "Only the file owner can revoke access"}), 403

    existing_share = fetch_one(
        """
        SELECT id
        FROM shares
        WHERE file_id = ? AND user_id = ?
        """,
        (file_id, target_user_id),
    )

    if existing_share is None:
        return jsonify({"error": "Share not found"}), 404

    execute_query(
        """
        DELETE FROM shares
        WHERE file_id = ? AND user_id = ?
        """,
        (file_id, target_user_id),
    )

    return jsonify({
        "message": "File access revoked successfully",
        "file_id": file_id,
        "user_id": target_user_id,
    }), 200


@files_bp.put("/<int:file_id>/edit")
def edit_file(file_id):

    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    if not can_write_file(file_id, user_id):
        return jsonify({"error": "Write permission required"}), 403

    file_record = fetch_one(
        "SELECT * FROM files WHERE id = ?",
        (file_id,),
    )

    if file_record is None:
        return jsonify({"error": "File not found"}), 404

    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return jsonify({"error": "No replacement file provided"}), 400

    if not uploaded_file.filename:
        return jsonify({"error": "Filename is required"}), 400

    new_content = uploaded_file.stream.read(
        current_app.config["MAX_CONTENT_LENGTH"] + 1
    )

    if not new_content:
        return jsonify({"error": "Empty files are not allowed"}), 400

    if len(new_content) > current_app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "File is too large"}), 413

    try:
        # Validate the existing file before replacing it.
        old_content = read_original_content(file_record)

        if file_record["is_encrypted"]:
            new_stored_content = encrypt_file(new_content)
        else:
            new_stored_content = new_content

        file_path = get_storage_file(file_record["stored_name"])

        if file_path is None:
            return jsonify({"error": "Invalid stored file"}), 500

        # Replace the file on disk.
        file_path.write_bytes(new_stored_content)

        new_hash = hashlib.sha256(new_content).hexdigest()

        try:
            execute_query(
                """
                UPDATE files
                SET file_size = ?,
                    sha256_hash = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (len(new_content), new_hash, file_id),
            )

        except Exception:
            # Restore original contents if the metadata update fails.
            if file_record["is_encrypted"]:
                file_path.write_bytes(encrypt_file(old_content))
            else:
                file_path.write_bytes(old_content)

            raise

        return jsonify({
            "message": "File updated successfully",
            "file_id": file_id,
            "file_size": len(new_content),
            "sha256_hash": new_hash,
        }), 200

    except EncryptionError:
        current_app.logger.exception("File encryption/decryption failed")
        return jsonify({"error": "Unable to process file encryption"}), 500

    except ValueError:
        return jsonify({
            "error": "Existing file integrity verification failed"
        }), 409

    except FileNotFoundError:
        return jsonify({"error": "Stored file is missing"}), 404

    except OSError:
        current_app.logger.exception("File editing failed")
        return jsonify({"error": "Unable to update file"}), 500