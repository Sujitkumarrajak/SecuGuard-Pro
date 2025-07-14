from fpdf import FPDF
import datetime
import os

def generate_pdf_report(filename, file_hash, scan_result, user):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="SecuGuard-Pro Scan Report", ln=True, align="C")
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Scanned by: {user}", ln=True)
    pdf.cell(200, 10, txt=f"Date: {now}", ln=True)
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Filename: {filename}", ln=True)
    pdf.cell(200, 10, txt=f"SHA256: {file_hash}", ln=True)
    pdf.cell(200, 10, txt=f"Scan Status: {scan_result['status']}", ln=True)
    pdf.ln(10)

    if "scan_summary" in scan_result:
        pdf.cell(200, 10, txt="Scan Summary:", ln=True)
        for key, value in scan_result["scan_summary"].items():
            pdf.cell(200, 10, txt=f"  - {key}: {value}", ln=True)

    reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
    os.makedirs(reports_dir, exist_ok=True)

    report_path = os.path.join(reports_dir, f"{filename}_report.pdf")
    pdf.output(report_path)

    return os.path.abspath(report_path)