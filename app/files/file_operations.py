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

    # 1. Verify user authentication.
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Authentication required"
        }), 401

    # 2. Check whether a file was provided.
    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return jsonify({
            "error": "No file provided"
        }), 400

    if not uploaded_file.filename:
        return jsonify({
            "error": "Filename is required"
        }), 400

    # 3. Sanitize the original filename.
    original_name = secure_filename(uploaded_file.filename)

    if not original_name:
        return jsonify({
            "error": "Invalid filename"
        }), 400

    # 4. Validate the file extension.
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({
            "error": "File type not allowed"
        }), 400

    # 5. Read and validate file size.
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

    # 6. Generate a unique storage filename.
    stored_name = f"{uuid.uuid4().hex}{extension}"

    storage_path = Path(current_app.config["STORAGE_PATH"])
    storage_path.mkdir(parents=True, exist_ok=True)

    destination = storage_path / stored_name

    # 7. Calculate SHA-256 integrity hash.
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    # 8. Identify MIME type.
    mime_type = mimetypes.guess_type(original_name)[0]

    if mime_type is None:
        mime_type = "application/octet-stream"

    # 9. Save file and database metadata.
    try:
        with destination.open("xb") as file:
            file.write(file_content)

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
                0,
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
            "message": "File uploaded successfully",
            "file_id": saved_file["id"],
            "original_name": original_name,
            "stored_name": stored_name,
            "file_size": len(file_content),
            "mime_type": mime_type,
            "sha256_hash": sha256_hash,
            "is_encrypted": False,
        }), 201

    except Exception:
        # Remove the physical file if database storage fails.
        destination.unlink(missing_ok=True)

        current_app.logger.exception(
            "File upload failed"
        )

        return jsonify({
            "error": "File upload failed"
        }), 500