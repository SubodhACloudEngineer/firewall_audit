"""
Flask Routes
Handles file uploads, triggers the audit pipeline, and returns results.
"""

import logging
import uuid
import base64
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file, current_app, render_template

from app.ingestion.matrix_parser import parse_matrix, load_zone_assignments
from app.ingestion.rulebase_parser import parse_rulebase
from app.ingestion.normalizer import normalize_all
from app.validation.engine import run_audit
from app.reporting.excel_report import generate_excel_report
from app.reporting.pdf_report import generate_pdf_report

logger = logging.getLogger(__name__)
bp = Blueprint("audit", __name__)

ALLOWED_MATRIX_EXT = {".xlsx", ".xls"}
ALLOWED_RULEBASE_EXT = {".csv"}


def _allowed(filename: str, allowed: set) -> bool:
    return Path(filename).suffix.lower() in allowed


_STATIC_DIR = Path(__file__).resolve().parent / "static"

# Candidate logo filenames tried in order; first match wins.
# Covers the correct name, the accidental double-extension, and the SVG variant.
_LOGO_CANDIDATES = [
    ("ntt_data_logo.png",     "image/png"),
    ("ntt_data_logo.png.png", "image/png"),
    ("logo.png",              "image/png"),
    ("logo.svg",              "image/svg+xml"),
]


def _load_logo_src() -> str:
    """Return a base64 data-URL for the first logo file found, or empty string."""
    for filename, mime in _LOGO_CANDIDATES:
        path = _STATIC_DIR / filename
        if path.exists():
            data = base64.b64encode(path.read_bytes()).decode()
            logger.info(f"Logo loaded from {path}")
            return f"data:{mime};base64,{data}"
    logger.warning(f"Logo not found in {_STATIC_DIR}. Tried: {[f for f,_ in _LOGO_CANDIDATES]}")
    return ""


@bp.route("/", methods=["GET"])
def index():
    return render_template("index.html", logo_src=_load_logo_src())


@bp.route("/upload", methods=["POST"])
def upload_and_audit():
    """
    POST /upload
    Expects multipart/form-data with:
      - matrix:   .xlsx file (Security Policy Matrix)
      - rulebase: .csv file  (Palo Alto rulebase export)

    Returns JSON audit result including download URLs for Excel and PDF reports.
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
        zone_map     = load_zone_assignments(matrix_path)   # raw zone → ATPSG zone
        firewall_rules = parse_rulebase(rulebase_path)
        policy_rules, firewall_rules = normalize_all(policy_rules, firewall_rules, zone_map)

        # Validation — pass zone_map so the intra-zone lateral-movement check
        # can resolve raw sub-zone names back to canonical ATPSG zones.
        result = run_audit(policy_rules, firewall_rules, zone_map)

        # Generate and persist reports
        report_dir = Path(current_app.config["REPORT_FOLDER"]) / job_id
        report_dir.mkdir(parents=True, exist_ok=True)

        excel_path = report_dir / "report.xlsx"
        pdf_path   = report_dir / "report.pdf"

        excel_path.write_bytes(generate_excel_report(result))
        pdf_path.write_bytes(generate_pdf_report(result))

        logger.info(f"Job {job_id}: reports saved to {report_dir}")

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
            "download_excel":       f"/download/{job_id}/excel",
            "download_pdf":         f"/download/{job_id}/pdf",
        }), 200

    except ValueError as e:
        logger.error(f"Job {job_id}: validation error: {e}")
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        logger.exception(f"Job {job_id}: unexpected error")
        return jsonify({"error": "Internal error during audit. Check server logs."}), 500


@bp.route("/download/<job_id>/excel", methods=["GET"])
def download_excel(job_id: str):
    """Serve the Excel report for a completed audit job."""
    report_path = Path(current_app.config["REPORT_FOLDER"]) / job_id / "report.xlsx"
    if not report_path.exists():
        return jsonify({"error": "Report not found. Please re-run the audit."}), 404
    return send_file(
        report_path,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=f"firewall_audit_{job_id[:8]}.xlsx",
    )


@bp.route("/download/<job_id>/pdf", methods=["GET"])
def download_pdf(job_id: str):
    """Serve the PDF report for a completed audit job."""
    report_path = Path(current_app.config["REPORT_FOLDER"]) / job_id / "report.pdf"
    if not report_path.exists():
        return jsonify({"error": "Report not found. Please re-run the audit."}), 404
    return send_file(
        report_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"firewall_audit_{job_id[:8]}.pdf",
    )
