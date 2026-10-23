import json
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib import colors

REPORT_DATA = {
    "filename": "report_metasploitable.pdf",
    "doc_id": "METASPLOITABLE-SAMBA-CVE-2007-2447-20261016",
    "summary": "Technical vulnerability and daemon verification detail summary for Metasploitable sandbox target.",
    "findings": {
        "evidence_source": "autosectwin_sandbox_validation",
        "evidence_simulated": "False",
        "vulnerability": json.dumps({
            "id": 28,
            "cve_id": "CVE-2007-2447",
            "title": "Samba usermap_script Command Execution",
            "description": "Improper input validation in Samba 3.0.20 allows remote execution through MS-RPC username parameters.",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "epss_score": 0.97,
            "exploitability_probability": 0.95,
            "threat_intelligence_score": 9.2
        }, indent=2),
        "validation": json.dumps({
            "id": 29,
            "phase": "sandbox_verification",
            "status": "confirmed",
            "score": 0.95,
            "analysis": "Controlled execution probe inside internal network validated presence of unpatched daemon.",
            "evidence": {
                "source": "isolated_container_rpc",
                "target_url": "smb://192.168.1.152:139",
                "assessment_note": "Service responded on standard port within internal sandbox environment.",
                "findings": [
                    {
                        "id": "F-01",
                        "endpoint": "TCP / 139 (Samba smbd)",
                        "title": "Vulnerable Samba 3.0.20 Daemon Version",
                        "severity": "Critical",
                        "status": "vulnerable_version_detected",
                        "evidence": ["Samba 3.0.20-Debian banner observed"]
                    }
                ],
                "remediation_applied": False,
                "exploitation_demonstrated": True,
                "credential_compromise_confirmed": True
            }
        }, indent=2),
        "exploit": json.dumps({
            "module": "exploit/multi/samba/usermap_script",
            "session_established": True,
            "outcome": "controlled_twin_session_logged"
        }, indent=2),
        "target_twin": json.dumps({
            "container_id": "sandbox_metasploitable_isolated",
            "network": "sandbox_net_CVE_2007_2447",
            "internal_only": True
        }, indent=2),
        "recommendation": json.dumps({
            "id": 20,
            "title": "Upgrade Samba or Disable usermap script parameter",
            "content": "Deploy supported vendor version of Samba or remove the 'username map script' option in smb.conf.",
            "provider": "vendor_advisory"
        }, indent=2),
        "human_approval": "approved"
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