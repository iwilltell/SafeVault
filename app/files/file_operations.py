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
from app.files.encryption import encrypt_file, decrypt_file, EncryptionError


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
    Return a file only if the user owns it or has shared access.
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


@files_bp.post("/upload")
def upload_file():

    # 1. Verify authentication.
    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    # 2. Check uploaded file.
    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return jsonify({"error": "No file provided"}), 400

    if not uploaded_file.filename:
        return jsonify({"error": "Filename is required"}), 400

    # 3. Sanitize filename.
    original_name = secure_filename(uploaded_file.filename)

    if not original_name:
        return jsonify({"error": "Invalid filename"}), 400

    # 4. Validate extension.
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "File type not allowed"}), 400

    # 5. Read and validate size.
    max_size = current_app.config["MAX_CONTENT_LENGTH"]
    file_content = uploaded_file.stream.read(max_size + 1)

    if not file_content:
        return jsonify({"error": "Empty files are not allowed"}), 400

    if len(file_content) > max_size:
        return jsonify({"error": "File is too large"}), 413

    # 6. Calculate hash of original content.
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    # 7. Encrypt before storing.
    try:
        encrypted_content = encrypt_file(file_content)
    except EncryptionError:
        current_app.logger.exception("File encryption failed")
        return jsonify({"error": "File encryption failed"}), 500

    # 8. Generate unique storage filename.
    stored_name = f"{uuid.uuid4().hex}{extension}"

    storage_path = Path(current_app.config["STORAGE_PATH"])
    storage_path.mkdir(parents=True, exist_ok=True)

    destination = storage_path / stored_name

    # 9. Determine MIME type.
    mime_type = mimetypes.guess_type(original_name)[0]
    mime_type = mime_type or "application/octet-stream"

    # 10. Save encrypted content and metadata.
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
            """
            SELECT id
            FROM files
            WHERE stored_name = ?
            """,
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

    # 1. Verify authentication.
    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    # 2. Retrieve owned and shared files.
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

    # 1. Verify authentication.
    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    # 2. Verify ownership or shared access.
    file_record = get_file_access(file_id, user_id)

    if file_record is None:
        # Same response for nonexistent and inaccessible files.
        return jsonify({"error": "File not found"}), 404

    # 3. Resolve the storage location safely.
    storage_path = Path(
        current_app.config["STORAGE_PATH"]
    ).resolve()

    stored_name = file_record["stored_name"]

    # Stored filenames are generated by SafeVault.
    if Path(stored_name).name != stored_name:
        current_app.logger.error("Invalid stored filename in database")
        return jsonify({"error": "Invalid stored file"}), 500

    file_path = (storage_path / stored_name).resolve()

    if file_path.parent != storage_path:
        return jsonify({"error": "Invalid stored file"}), 500

    # 4. Check that the physical file exists.
    if not file_path.is_file():
        return jsonify({"error": "Stored file is missing"}), 404

    try:
        stored_content = file_path.read_bytes()

        # 5. Decrypt if encryption is enabled.
        if file_record["is_encrypted"]:
            original_content = decrypt_file(stored_content)
        else:
            original_content = stored_content

        # 6. Verify original content integrity.
        actual_hash = hashlib.sha256(
            original_content
        ).hexdigest()

        if actual_hash != file_record["sha256_hash"]:
            current_app.logger.error(
                "File integrity verification failed for file ID %s",
                file_id,
            )

            return jsonify({
                "error": "File integrity verification failed"
            }), 409

        # 7. Return the original file.
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

        return jsonify({
            "error": "Unable to decrypt file"
        }), 500

    except OSError:
        current_app.logger.exception(
            "File read failed for file ID %s",
            file_id,
        )

        return jsonify({
            "error": "Unable to read stored file"
        }), 500