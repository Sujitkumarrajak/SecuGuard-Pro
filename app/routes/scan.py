from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from app.utils import get_file_hash, scan_file_with_virustotal, generate_pdf_report  

from app import limiter  # ✅ this line is needed

import os
import uuid

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/upload', methods=['POST'])
@jwt_required()
@limiter.limit("5 per minute")  # ✅ rate limiting
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    file_id = str(uuid.uuid4())
    save_path = os.path.join('uploads', f"{file_id}_{filename}")
    os.makedirs('uploads', exist_ok=True)
    file.save(save_path)

    # ✅ Get file hash (used for reporting)
    file_hash = get_file_hash(file)

    # ✅ Scan using VirusTotal
    vt_response = scan_file_with_virustotal(save_path)

    # ✅ Get the current user's identity
    current_user = get_jwt_identity()

    # ✅ Generate report PDF
    report_path = generate_pdf_report(
        filename=filename,
        file_hash=file_hash,
        scan_result=vt_response,
        user=current_user
    )

    # ✅ Return scan summary if available
    scan_summary = vt_response.get("scan_summary", {})

    result = {
        "file_hash": file_hash,
        "filename": filename,
        "scan_summary": scan_summary,
        "scan_result": vt_response,
        "report": f"/download/{os.path.basename(report_path)}"
    }

    return jsonify(result), 200

   