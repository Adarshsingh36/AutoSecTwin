import json
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib import colors

REPORT_DATA = {
    "filename": "report_juiceshop.pdf",
    "doc_id": "JUICESHOP-FTP-EXPOSURE-20261016",
    "summary": "Technical vulnerability and exploitation detail summary.",
    "findings": {
        "evidence_source": "user_submitted_evidence",
        "evidence_simulated": "False",
        "vulnerability": json.dumps({
            "id": 24,
            "cve_id": "JUICESHOP-FTP-EXPOSURE-20261016",
            "title": "Juice Shop FTP Directory Listing and File Exposure",
            "description": "Metasploit-assisted HTTP testing confirmed that /ftp/ exposes a directory listing and that /ftp/incident-support.kdbx is accessible without authentication. The file contents and impact have not been verified.",
            "severity": "MEDIUM",
            "cvss_score": 0.0,
            "epss_score": 0.0,
            "exploitability_probability": 0.005,
            "threat_intelligence_score": 0.0
        }, indent=2),
        "validation": json.dumps({
            "id": 25,
            "phase": "initial",
            "status": "inconclusive",
            "score": 0.0,
            "analysis": "Legacy validation evidence contains no success markers or definitive execution outcome.",
            "evidence": {
                "source": "user_submitted_http_assessment",
                "target_url": "http://192.168.56.1:3000",
                "assessment_note": "Directory and file exposure were observed; no successful application exploit, credential compromise, or remediation was demonstrated.",
                "tests_not_establishing_vulnerability": [
                    "Juice Shop reachability returned HTTP 200.",
                    "GraphQL introspection was not demonstrated.",
                    "/rest/user/whoami returned an empty user object."
                ],
                "findings": [
                    {
                        "id": "F-01",
                        "endpoint": "GET /ftp/",
                        "title": "Exposed FTP directory listing",
                        "severity": "Medium",
                        "status": "confirmed_directory_listing",
                        "http_status": 200,
                        "evidence": ["incident-support.kdbx", "announcement_encrypted.md", "coupons_2013.md.bak", "package.json.bak", "suspicious_errors.yml"],
                        "impact": "File contents and sensitivity require further verification."
                    },
                    {
                        "id": "F-02",
                        "endpoint": "GET /ftp/incident-support.kdbx",
                        "title": "Unauthenticated KDBX file access",
                        "severity": "Medium - provisional",
                        "status": "file_exposure_confirmed_contents_unverified",
                        "http_status": 200,
                        "content_type": "application/octet-stream",
                        "content_length": 3246
                    },
                    {
                        "id": "F-03",
                        "endpoints": ["/", "/api/Challenges"],
                        "title": "Permissive CORS response",
                        "severity": "Needs validation",
                        "status": "wildcard_observed_exploitability_not_demonstrated",
                        "observed_header": "Access-Control-Allow-Origin: *"
                    }
                ],
                "remediation_applied": False,
                "exploitation_demonstrated": False,
                "credential_compromise_confirmed": False
            }
        }, indent=2),
        "exploit": "n/a",
        "target_twin": "n/a",
        "recommendation": json.dumps({
            "id": 18,
            "title": "Apply vendor patch for JUICESHOP-FTP-EXPOSURE-20261016",
            "content": "Check vendor security advisories for affected product, deploy the fixed release, and revalidate the vulnerability in the Digital Twin.",
            "provider": "vendor_lookup"
        }, indent=2),
        "human_approval": "n/a"
    }
}

def generate_pdf(report_entry):
    pdf_filename = report_entry["filename"]
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(name="ReportTitle", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=colors.HexColor("#1A2B49"), spaceAfter=14)
    section_heading = ParagraphStyle(name="SectionHeading", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=colors.HexColor("#2C3E50"), spaceBefore=8, spaceAfter=4)
    summary_text = ParagraphStyle(name="SummaryText", parent=styles["Normal"], fontName="Helvetica", fontSize=9.5, leading=13, textColor=colors.HexColor("#333333"), spaceAfter=10)
    table_key_style = ParagraphStyle(name="TableKey", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.HexColor("#1A2B49"))
    table_val_style = ParagraphStyle(name="TableVal", parent=styles["Normal"], fontName="Courier", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#222222"))

    story = [
        Paragraph(f"AutoSecTwin Validation Report &mdash; {report_entry['doc_id']}", title_style),
        Paragraph("Summary", section_heading),
        Paragraph(report_entry["summary"], summary_text),
        Paragraph("Findings", section_heading)
    ]

    table_data = []
    for key, val in report_entry["findings"].items():
        safe_val = val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>").replace(" ", "&nbsp;")
        table_data.append([Paragraph(key, table_key_style), Paragraph(safe_val, table_val_style)])

    report_table = Table(table_data, colWidths=[120, 420], repeatRows=0)
    report_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
        ('LINEBEFORE', (1, 0), (1, -1), 0.5, colors.HexColor("#D0D7DE")),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
    ]))

    story.append(report_table)
    doc.build(story)
    print(f"[+] Successfully generated: {pdf_filename}")

if __name__ == "__main__":
    generate_pdf(REPORT_DATA)