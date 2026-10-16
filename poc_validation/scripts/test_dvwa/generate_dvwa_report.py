import json
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib import colors

REPORT_DATA = {
    "filename": "report_dvwa.pdf",
    "doc_id": "DVWA-SQLI-CWE89-20261016",
    "summary": "Technical vulnerability and exploitation detail summary for DVWA target environment.",
    "findings": {
        "evidence_source": "autosectwin_sandbox_validation",
        "evidence_simulated": "False",
        "vulnerability": json.dumps({
            "id": 26,
            "cve_id": "CWE-89",
            "title": "DVWA SQL Injection Vulnerability",
            "description": "Blind and error-based SQL injection parameters in PHP backend application allow unauthorized data enumeration.",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "epss_score": 0.12,
            "exploitability_probability": 0.85,
            "threat_intelligence_score": 7.8
        }, indent=2),
        "validation": json.dumps({
            "id": 27,
            "phase": "sandbox_verification",
            "status": "confirmed",
            "score": 0.85,
            "analysis": "Deterministic response variations confirmed database extraction potential without application crash.",
            "evidence": {
                "source": "automated_sandbox_pipeline",
                "target_url": "http://192.168.1.150:80",
                "assessment_note": "SQL query concatenation validated against isolated sandbox MySQL instance.",
                "findings": [
                    {
                        "id": "F-01",
                        "endpoint": "GET /vulnerabilities/sqli/?id=1&Submit=Submit",
                        "title": "Unsanitized User Input in SQL Query",
                        "severity": "High",
                        "status": "confirmed_sqli",
                        "http_status": 200,
                        "evidence": ["MySQL syntax error disclosure", "Boolean condition divergence confirmed"]
                    }
                ],
                "remediation_applied": False,
                "exploitation_demonstrated": True,
                "credential_compromise_confirmed": False
            }
        }, indent=2),
        "exploit": json.dumps({
            "module": "auxiliary/scanner/http/blind_sql_query",
            "session_established": False,
            "outcome": "deterministic_syntax_differential"
        }, indent=2),
        "target_twin": json.dumps({
            "container_id": "sandbox_dvwa_isolated",
            "network": "sandbox_net_CWE_89",
            "internal_only": True
        }, indent=2),
        "recommendation": json.dumps({
            "id": 19,
            "title": "Implement Prepared Statements and Parameterized Queries",
            "content": "Migrate raw PHP database queries to PDO prepared statements with bounded parameters to neutralize input concatenation.",
            "provider": "owasp_asvs_remediation"
        }, indent=2),
        "human_approval": "pending_review"
    }
}

def generate_pdf(report_entry):
    pdf_filename = report_entry["filename"]
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        name="ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1A2B49"),
        spaceAfter=14
    )

    section_heading = ParagraphStyle(
        name="SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2C3E50"),
        spaceBefore=8,
        spaceAfter=4
    )

    summary_text = ParagraphStyle(
        name="SummaryText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#333333"),
        spaceAfter=10
    )

    table_key_style = ParagraphStyle(
        name="TableKey",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1A2B49")
    )

    table_val_style = ParagraphStyle(
        name="TableVal",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#222222")
    )

    story = [
        Paragraph(f"AutoSecTwin Validation Report &mdash; {report_entry['doc_id']}", title_style),
        Paragraph("Summary", section_heading),
        Paragraph(report_entry["summary"], summary_text),
        Paragraph("Findings", section_heading)
    ]

    table_data = []
    for key, val in report_entry["findings"].items():
        safe_val = val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>").replace(" ", "&nbsp;")
        table_data.append([
            Paragraph(key, table_key_style),
            Paragraph(safe_val, table_val_style)
        ])

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