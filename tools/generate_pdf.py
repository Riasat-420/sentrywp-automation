import os
import re
import subprocess
import markdown
import http.server
import socket
import threading
import time

def main():
    md_path = "client-security-report.md"
    html_path = "client-security-report.html"
    pdf_path = "client-security-report.pdf"


    if not os.path.exists(md_path):
        print(f"Error: Markdown file not found at {md_path}")
        return

    with open(md_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    # Split title / cover metadata and report body
    # We will build a beautiful HTML structure.
    
    # 1. Parse markdown to HTML
    html_body = markdown.markdown(md_content, extensions=['extra', 'nl2br'])

    # Post-process GitHub-style alerts in the converted HTML
    # Warning callouts
    html_body = html_body.replace("<blockquote>\n<p>[!WARNING]", '<div class="alert-warning"><strong>WARNING:</strong> ')
    # Important callouts
    html_body = html_body.replace("<blockquote>\n<p>[!IMPORTANT]", '<div class="alert-important"><strong>IMPORTANT:</strong> ')
    # Note callouts
    html_body = html_body.replace("<blockquote>\n<p>[!NOTE]", '<div class="alert-note"><strong>NOTE:</strong> ')
    # Close custom divs
    html_body = html_body.replace("</p>\n</blockquote>", "</div>")
    html_body = html_body.replace("</blockquote>", "</div>")

    # Add custom page breaks for key headers to ensure excellent layout
    html_body = html_body.replace("<h3>THE DEVASTATING CONSEQUENCES", '<h3 class="page-break">THE DEVASTATING CONSEQUENCES')
    html_body = html_body.replace("<h3>BY THE NUMBERS:", '<h3 class="page-break">BY THE NUMBERS:')
    html_body = html_body.replace("<h3>TECHNICAL ANATOMY OF", '<h3 class="page-break">TECHNICAL ANATOMY OF')
    html_body = html_body.replace("<h3>POST-RESTORATION HARDENING", '<h3 class="page-break">POST-RESTORATION HARDENING')

    # Convert WhatsApp raw text link into a gorgeous stylized card
    # We will search for the WhatsApp contact block in HTML and wrap it inside a card
    whatsapp_pattern = r'<p><strong>Muhammad Riasat Ali</strong><br />\s*<em>Senior Web Developer &amp; Security Specialist</em><br />\s*<a href="https://wa.me/923498088939">Contact Me on WhatsApp</a><br />\s*<strong>WhatsApp:</strong> \+923498088939\s*</p>'
    
    whatsapp_card_html = """
    <div class="whatsapp-card">
        <h3>Direct Emergency & Maintenance Contact</h3>
        <p>If you have any questions, require regular security audits, or need assistance keeping your digital asset safe, please reach out directly. I am here to protect your business.</p>
        <p><strong>Muhammad Riasat Ali</strong><br><em>Senior Web Developer &amp; WordPress Security Specialist</em></p>
        <a href="https://wa.me/923498088939" class="whatsapp-btn">Contact Me on WhatsApp</a>
    </div>
    """
    
    html_body = re.sub(whatsapp_pattern, whatsapp_card_html, html_body)
    
    # If the above replacement failed due to white spaces, let's do a broader replacement
    if whatsapp_card_html not in html_body:
        broad_whatsapp_pattern = r'<p><strong>Muhammad Riasat Ali</strong>.*?\+923498088939.*?</p>'
        html_body = re.sub(broad_whatsapp_pattern, whatsapp_card_html, html_body, flags=re.DOTALL)

    # Let's clean up any residual markdown symbols that look raw in HTML
    # (e.g. # CRITICAL CYBERSECURITY EMERGENCY REPORT being parsed twice, or keeping the first-level title out of body since it is in cover)
    # We will hide the first raw title inside the body, since we are building a stunning custom Cover Page.
    html_body = re.sub(r'<h1>CRITICAL CYBERSECURITY EMERGENCY REPORT</h1>\s*<h2>EMERGENCY MALWARE ERADICATION.*?</h2>.*?<hr />', '', html_body, flags=re.DOTALL)

    # Build the full HTML page with the modern CSS styling and the Cover Page
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit & Malware Cleanup Report - assp.dk</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap');

        :root {{
            --primary-color: #be123c; /* premium crimson red */
            --primary-dark: #881337;
            --secondary-color: #0f172a; /* deep slate */
            --secondary-light: #1e293b;
            --text-color: #334155;
            --text-light: #64748b;
            --bg-color: #ffffff;
            --border-color: #e2e8f0;
            --success-color: #10b981;
        }}

        body {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: var(--bg-color);
            font-size: 14.5px;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }}

        /* Print Page Setup */
        @page {{
            size: A4;
            margin: 20mm 18mm 20mm 18mm;
        }}

        /* Cover Page styling */
        .cover-page {{
            page-break-after: always;
            height: 250mm;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            box-sizing: border-box;
            padding: 30mm 10mm 10mm 10mm;
            position: relative;
        }}

        .cover-page::before {{
            content: "";
            position: absolute;
            top: 0;
            left: -10mm;
            width: 8px;
            height: 100%;
            background-color: var(--primary-color);
        }}

        .cover-header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 25px;
        }}

        .cover-badge {{
            background-color: var(--primary-color);
            color: white;
            padding: 6px 12px;
            font-family: 'Outfit', sans-serif;
            font-weight: 700;
            font-size: 11px;
            letter-spacing: 2px;
            text-transform: uppercase;
            display: inline-block;
            border-radius: 4px;
            margin-bottom: 25px;
        }}

        .cover-title {{
            font-family: 'Outfit', sans-serif;
            font-size: 34px;
            line-height: 1.15;
            color: var(--secondary-color);
            margin: 0;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: -0.5px;
        }}

        .cover-subtitle {{
            font-family: 'Outfit', sans-serif;
            font-size: 15px;
            color: var(--primary-color);
            margin-top: 15px;
            margin-bottom: 0;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}

        .cover-middle {{
            margin-top: 60px;
            margin-bottom: 60px;
        }}

        .cover-card {{
            background-color: #f8fafc;
            border-left: 5px solid var(--secondary-color);
            padding: 30px;
            border-radius: 0 8px 8px 0;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
        }}

        .cover-card p {{
            margin: 0 0 15px 0;
            font-size: 15px;
            color: var(--text-color);
            text-align: left;
        }}

        .cover-card p:last-child {{
            margin-bottom: 0;
        }}

        .cover-card strong {{
            color: var(--primary-color);
            font-weight: 700;
        }}

        .cover-footer {{
            margin-top: auto;
            border-top: 1px solid var(--border-color);
            padding-top: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            width: 100%;
        }}

        .meta-group {{
            margin-bottom: 5px;
        }}

        .meta-label {{
            font-size: 10px;
            text-transform: uppercase;
            color: var(--text-light);
            letter-spacing: 1.5px;
            margin: 0 0 5px 0;
            font-weight: 600;
        }}

        .meta-val {{
            font-size: 14px;
            font-weight: 700;
            color: var(--secondary-color);
            margin: 0;
        }}

        .meta-val-dev {{
            color: var(--primary-color);
        }}

        /* Report Body Content Styles */
        .report-content {{
            padding: 5mm 10mm;
        }}

        .report-content h1, 
        .report-content h2, 
        .report-content h3, 
        .report-content h4 {{
            font-family: 'Outfit', sans-serif;
            color: var(--secondary-color);
            font-weight: 700;
            page-break-inside: avoid;
        }}

        .report-content h1 {{
            font-size: 24px;
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 8px;
            margin-top: 0;
            text-transform: uppercase;
            letter-spacing: -0.5px;
        }}

        .report-content h2 {{
            font-size: 19px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 6px;
            margin-top: 35px;
            text-transform: uppercase;
        }}

        .report-content h3 {{
            font-size: 16px;
            color: var(--secondary-light);
            margin-top: 30px;
            text-transform: uppercase;
            border-left: 4px solid var(--primary-color);
            padding-left: 12px;
        }}

        .report-content h4 {{
            font-size: 14.5px;
            color: var(--primary-color);
            margin-top: 25px;
        }}

        p {{
            margin-top: 0;
            margin-bottom: 1.2em;
            text-align: justify;
            color: var(--text-color);
        }}

        strong {{
            font-weight: 700;
            color: var(--secondary-color);
        }}

        ul, ol {{
            margin-top: 0;
            margin-bottom: 1.5em;
            padding-left: 22px;
        }}

        li {{
            margin-bottom: 8px;
            color: var(--text-color);
        }}

        hr {{
            border: 0;
            border-top: 1px solid var(--border-color);
            margin: 30px 0;
            page-break-inside: avoid;
        }}

        /* Customized Alarm Alert Callout boxes */
        .alert-warning {{
            background-color: #fff1f2;
            border-left: 5px solid var(--primary-color);
            color: #9f1239;
            padding: 18px;
            margin: 25px 0;
            border-radius: 0 8px 8px 0;
            page-break-inside: avoid;
        }}

        .alert-warning strong {{
            color: #881337;
            font-family: 'Outfit', sans-serif;
            font-weight: 700;
        }}

        .alert-important {{
            background-color: #f0fdf4;
            border-left: 5px solid #16a34a;
            color: #14532d;
            padding: 18px;
            margin: 25px 0;
            border-radius: 0 8px 8px 0;
            page-break-inside: avoid;
        }}

        .alert-important strong {{
            color: #14532d;
            font-family: 'Outfit', sans-serif;
            font-weight: 700;
        }}

        .alert-note {{
            background-color: #f8fafc;
            border-left: 5px solid #64748b;
            color: #334155;
            padding: 18px;
            margin: 25px 0;
            border-radius: 0 8px 8px 0;
            page-break-inside: avoid;
        }}

        .alert-note strong {{
            color: #0f172a;
            font-family: 'Outfit', sans-serif;
            font-weight: 700;
        }}

        /* WhatsApp Card */
        .whatsapp-card {{
            margin-top: 50px;
            background-color: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-left: 5px solid #22c55e;
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            page-break-inside: avoid;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.02);
        }}

        .whatsapp-card h3 {{
            color: #14532d;
            margin-top: 0;
            font-size: 19px;
            font-family: 'Outfit', sans-serif;
            border-left: none;
            padding-left: 0;
            text-transform: none;
        }}

        .whatsapp-card p {{
            color: #166534;
            text-align: center;
            font-size: 14.5px;
            margin-bottom: 20px;
        }}

        .whatsapp-btn {{
            display: inline-block;
            background-color: #22c55e;
            color: white !important;
            text-decoration: none;
            font-weight: 700;
            padding: 12px 35px;
            border-radius: 50px;
            font-size: 14.5px;
            box-shadow: 0 4px 10px rgba(34, 197, 94, 0.25);
            transition: all 0.2s ease;
            font-family: 'Outfit', sans-serif;
            letter-spacing: 0.5px;
        }}

        /* Helper Classes for Printing layout */
        .page-break {{
            page-break-before: always;
        }}
    </style>
</head>
<body>

    <!-- STUNNING COVER PAGE -->
    <div class="cover-page">
        <div class="cover-header">
            <span class="cover-badge">Emergency Response</span>
            <h1 class="cover-title">Critical Cybersecurity<br>Emergency Report</h1>
            <h2 class="cover-subtitle">Malware Eradication, Server Hardening & Disaster Recovery</h2>
        </div>
        
        <div class="cover-middle">
            <div class="cover-card">
                <p>This document details the emergency diagnostic, cleaning, and recovery protocols executed on <strong>assp.dk</strong>.</p>
                <p>The system was suffering from a critical, multi-tier cyber-intrusion designed to grant unauthorized backdoors, steal information, and compromise corporate reputation.</p>
                <p>Through immediate intervention, all vulnerabilities have been surgically patched, clean core code has been restored, and defensive walls have been locked down.</p>
            </div>
        </div>
        
        <div class="cover-footer">
            <div class="meta-grid">
                <div class="meta-group">
                    <h3 class="meta-label">Target Asset</h3>
                    <p class="meta-val">assp.dk</p>
                </div>
                <div class="meta-group">
                    <h3 class="meta-label">Lead Web Developer</h3>
                    <p class="meta-val meta-val-dev">Muhammad Riasat Ali</p>
                </div>
                <div class="meta-group">
                    <h3 class="meta-label">Date of Report</h3>
                    <p class="meta-val">May 28, 2026</p>
                </div>
                <div class="meta-group">
                    <h3 class="meta-label">Current Security Status</h3>
                    <p class="meta-val" style="color: #16a34a;">CLEAN & SECURED</p>
                </div>
            </div>
        </div>
    </div>

    <!-- MAIN REPORT CONTENT -->
    <div class="report-content">
        {html_body}
    </div>

</body>
</html>
"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"HTML report successfully compiled and saved to {html_path}")

    # 3. Convert to PDF via local HTTP server (avoids file:// path in footers)
    print("Compiling PDF utilizing Microsoft Edge in headless mode...")

    def pick_free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    port = pick_free_port()
    cwd = os.getcwd()
    httpd = http.server.HTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.4)

    pdf_url = f"http://127.0.0.1:{port}/{html_path}"
    edge_paths = [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ]
    edge_command = None
    for edge_bin in edge_paths:
        if os.path.exists(edge_bin):
            edge_command = [
                edge_bin,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--run-all-compositor-stages-before-draw",
                "--virtual-time-budget=10000",
                "--print-to-pdf-no-header",
                "--no-pdf-header-footer",
                f"--print-to-pdf={os.path.abspath(pdf_path)}",
                pdf_url,
            ]
            break

    if not edge_command:
        print("Error: Microsoft Edge not found.")
        httpd.shutdown()
        return

    try:
        subprocess.run(edge_command, capture_output=True, text=True, check=False, timeout=60)
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            print(f"SUCCESS: PDF report successfully generated at: {pdf_path}")
        else:
            print("Error: Edge completed but PDF file was not created or is empty.")
    except Exception as e:
        print(f"Error executing Edge compilation: {e}")
    finally:
        httpd.shutdown()
        httpd.server_close()

if __name__ == "__main__":
    main()
