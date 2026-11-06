import hashlib
import mimetypes
import uuid

from pathlib import Path

from flask import (
    Blueprint,
    jsonify,
    request,
    session,
    current_app,
)

from werkzeug.utils import secure_filename

from app.database.db import execute_query, fetch_one
from app.files.encryption import encrypt_file, EncryptionError


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


@files_bp.post("/upload")
def upload_file():

    # 1. Verify authentication.
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Authentication required"
        }), 401

    # 2. Check the uploaded file.
    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return jsonify({
            "error": "No file provided"
        }), 400

    if not uploaded_file.filename:
        return jsonify({
            "error": "Filename is required"
        }), 400

    # 3. Sanitize filename.
    original_name = secure_filename(uploaded_file.filename)

    if not original_name:
        return jsonify({
            "error": "Invalid filename"
        }), 400

    # 4. Validate extension.
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({
            "error": "File type not allowed"
        }), 400

    # 5. Read and validate size.
    max_size = current_app.config["MAX_CONTENT_LENGTH"]
    file_content = uploaded_file.stream.read(max_size + 1)

    if not file_content:
        return jsonify({
            "error": "Empty files are not allowed"
        }), 400

    if len(file_content) > max_size:
        return jsonify({
            "error": "File is too large"
        }), 413

    # 6. Calculate hash of the ORIGINAL file.
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    # 7. Encrypt file before storing it.
    try:
        encrypted_content = encrypt_file(file_content)
    except EncryptionError:
        current_app.logger.exception("File encryption failed")
        return jsonify({
            "error": "File encryption failed"
        }), 500

    # 8. Generate unique storage name.
    stored_name = f"{uuid.uuid4().hex}{extension}"

    storage_path = Path(current_app.config["STORAGE_PATH"])
    storage_path.mkdir(parents=True, exist_ok=True)

    destination = storage_path / stored_name

    # 9. Determine MIME type.
    mime_type = mimetypes.guess_type(original_name)[0]

    if mime_type is None:
        mime_type = "application/octet-stream"

    # 10. Save encrypted file and metadata.
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

        return jsonify({
            "error": "File upload failed"
        }), 500