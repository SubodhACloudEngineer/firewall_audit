"""
Flask Routes
Handles file uploads, triggers the audit pipeline, and returns results.
"""

import logging
import uuid
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file, current_app, render_template

from app.ingestion.matrix_parser import parse_matrix
from app.ingestion.rulebase_parser import parse_rulebase
from app.ingestion.normalizer import normalize_all
from app.validation.engine import run_audit

logger = logging.getLogger(__name__)
bp = Blueprint("audit", __name__)

ALLOWED_MATRIX_EXT = {".xlsx", ".xls"}
ALLOWED_RULEBASE_EXT = {".csv"}


def _allowed(filename: str, allowed: set) -> bool:
    return Path(filename).suffix.lower() in allowed


@bp.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@bp.route("/upload", methods=["POST"])
def upload_and_audit():
    """
    POST /upload
    Expects multipart/form-data with:
      - matrix:   .xlsx file (Security Policy Matrix)
      - rulebase: .csv file  (Palo Alto rulebase export)

    Returns JSON audit result.
    """
    if "matrix" not in request.files or "rulebase" not in request.files:
        return jsonify({"error": "Both 'matrix' and 'rulebase' files are required"}), 400

    matrix_file = request.files["matrix"]
    rulebase_file = request.files["rulebase"]

    if not _allowed(matrix_file.filename, ALLOWED_MATRIX_EXT):
        return jsonify({"error": "Matrix must be an .xlsx file"}), 400
    if not _allowed(rulebase_file.filename, ALLOWED_RULEBASE_EXT):
        return jsonify({"error": "Rulebase must be a .csv file"}), 400

    # Save uploads with unique job ID
    job_id = str(uuid.uuid4())
    upload_dir = Path(current_app.config["UPLOAD_FOLDER"]) / job_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    matrix_path = upload_dir / "matrix.xlsx"
    rulebase_path = upload_dir / "rulebase.csv"
    matrix_file.save(matrix_path)
    rulebase_file.save(rulebase_path)

    logger.info(f"Job {job_id}: files saved, starting audit")

    try:
        # Ingestion
        policy_rules = parse_matrix(matrix_path)
        firewall_rules = parse_rulebase(rulebase_path)
        policy_rules, firewall_rules = normalize_all(policy_rules, firewall_rules)

        # Validation
        result = run_audit(policy_rules, firewall_rules)

        # Serialize findings for JSON response
        findings_data = [
            {
                "rule_name":    f.rule_name,
                "finding_type": f.finding_type,
                "severity":     f.severity,
                "description":  f.description,
                "details":      f.details,
                "remediation":  f.remediation,
            }
            for f in result.findings
        ]

        return jsonify({
            "job_id":               job_id,
            "summary":              result.summary,
            "compliance_score":     result.compliance_score,
            "total_firewall_rules": result.total_firewall_rules,
            "total_policy_rules":   result.total_policy_rules,
            "findings_by_severity": result.findings_by_severity,
            "findings_by_type":     result.findings_by_type,
            "findings":             findings_data,
        }), 200

    except ValueError as e:
        logger.error(f"Job {job_id}: validation error: {e}")
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        logger.exception(f"Job {job_id}: unexpected error")
        return jsonify({"error": "Internal error during audit. Check server logs."}), 500
