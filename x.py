# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Modular Project Documentation & Codebase-to-PDF Bundler (Standalone Tool)
# Usage: python x.py [--type full|docs|code|logs|report]
# ==============================================================================
import os
import sys
import argparse
from datetime import datetime
from fpdf import FPDF

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend import db_manager


class ProjectPDF(FPDF):
    """Custom FPDF class providing standardized running header/footer."""
    def __init__(self, doc_title="Automated Threat Intel (ATI V2)"):
        super().__init__()
        self.doc_title = doc_title

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"{self.doc_title} | Page {self.page_no()}", align="C")


def generate_ascii_tree(source_folder, ignored_dirs):
    """Generates a clean text-based representation of the directory structure."""
    tree_lines = [f"{os.path.basename(os.path.abspath(source_folder))}/"]
    for root, dirs, files in os.walk(source_folder):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        level = root.replace(source_folder, '').count(os.sep)
        indent = ' ' * 4 * level
        
        if level > 0:
            tree_lines.append(f"{indent}{os.path.basename(root)}/")
            
        subindent = ' ' * 4 * (level + 1)
        for f in sorted(files):
            if f.startswith('.env') and f != '.env.example':
                continue
            if not f.endswith(('.html', '.pdf', '.pyc')):  
                tree_lines.append(f"{subindent}{f}")
                
    return "\n".join(tree_lines)


def generate_threat_dossier_pdf(output_filename=None, version="v2", top_n=30):
    """Generates an executive threat intelligence dossier PDF from the local SQLite database."""
    now = datetime.now()
    if not output_filename:
        date_stamp = now.strftime("%d-%b-%Y").upper()
        output_filename = f"ATI_Threat_Dossier_{version}_{date_stamp}.pdf"

    out_path = os.path.join(ROOT_DIR, output_filename) if not os.path.isabs(output_filename) else output_filename

    pdf = ProjectPDF(doc_title=f"ATI V2 Threat Intelligence Dossier ({now.strftime('%d-%b-%Y')})")
    pdf.set_auto_page_break(auto=True, margin=15)

    conn = db_manager.get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT m.cve_id, m.severity, m.cvss_v3_score, m.cvss_vector, m.epss_score,
               m.affected_vendor, m.affected_product, m.is_cisa_kev, m.has_public_poc,
               m.is_iot_ot, m.osint_mention_count,
               a.ai_summary, a.recommended_action, a.poc_recreation_steps, a.keywords, a.is_analyzed
        FROM cve_main m
        LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id
        ORDER BY 
            CASE 
                WHEN a.is_analyzed = 1 AND m.has_public_poc = 1 THEN 1
                WHEN a.is_analyzed = 1 THEN 2
                ELSE 3 
            END ASC,
            CASE m.severity 
                WHEN 'Critical' THEN 1 
                WHEN 'High' THEN 2 
                WHEN 'Medium' THEN 3 
                WHEN 'Low' THEN 4 
                ELSE 5 
            END ASC,
            m.cvss_v3_score DESC,
            m.epss_score DESC
        LIMIT ?
    """, (top_n,))
    threats = [dict(row) for row in cursor.fetchall()]
    conn.close()

    # Title Page
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 15, "Executive Threat Intelligence Dossier", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 8, f"Generated on {now.strftime('%Y-%m-%d %H:%M:%S')} | Version: {version.upper()}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Top {len(threats)} Prioritized Vulnerabilities", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5, "Ranked by AI weaponization status, Public PoC availability, CVSS severity, and EPSS exploit probability.")
    pdf.ln(6)

    for i, t in enumerate(threats, 1):
        cve_id = t['cve_id']
        sev = t['severity'] or 'Unknown'
        cvss = t['cvss_v3_score'] or 0.0
        vendor = t['affected_vendor'] or 'Unknown'
        prod = t['affected_product'] or 'Unknown'
        epss_str = f"{(float(t['epss_score']) * 100):.1f}%" if t['epss_score'] is not None else "NA"
        summary = t['ai_summary'] or "Analysis pending..."
        action = t['recommended_action'] or "Review manually"
        poc = t['poc_recreation_steps'] or "None"
        keywords = t['keywords'] or "None"

        pdf.set_font("Helvetica", "B", 11)
        tags = []
        if t['has_public_poc']: tags.append("[PoC Available]")
        if t['is_cisa_kev']: tags.append("[CISA KEV]")
        if t['is_iot_ot']: tags.append("[IoT/OT]")
        if t['is_analyzed']: tags.append("[AI Analyzed]")
        tag_str = " ".join(tags)

        pdf.cell(0, 7, f"{i}. {cve_id} | {sev} (CVSS: {cvss}, EPSS: {epss_str}) {tag_str}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(30, 5, "Target:", new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"{vendor} / {prod}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(30, 5, "Keywords:", new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"{keywords}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, "AI Executive Summary:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8.5)
        safe_sum = summary.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 4.5, safe_sum)

        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, "Recommended Action:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "I", 8.5)
        safe_act = action.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 4.5, safe_act)

        if poc and poc != "None" and poc != "None identified":
            pdf.set_font("Courier", "B", 8)
            pdf.cell(0, 5, "Proof of Concept / Recreation Payload:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 7.5)
            safe_poc = poc.encode('latin-1', 'replace').decode('latin-1')[:600]
            pdf.multi_cell(0, 3.8, safe_poc)

        pdf.ln(5)

    pdf.output(out_path)
    print(f"\n[+] Successfully generated Threat Dossier PDF: {out_path}")
    return os.path.basename(out_path)


def merge_project_files_to_pdf(source_folder=None, output_filename=None, version="v2", export_type="full"):
    """
    Modular PDF Generator:
    - export_type='full': Complete Codebase + Documentation + Logs
    - export_type='docs': Architecture & Markdown Documentation only
    - export_type='code': Python Source Code files only
    - export_type='logs': Operational Log files only
    - export_type='report': Executive Threat Intelligence Dossier
    """
    if export_type == "report":
        return generate_threat_dossier_pdf(output_filename=output_filename, version=version)

    if not source_folder or source_folder == ".":
        source_folder = ROOT_DIR

    now = datetime.now()
    if not output_filename:
        date_stamp = now.strftime("%d-%b-%Y").upper()
        suffix = f"_{export_type.upper()}" if export_type != "full" else ""
        output_filename = f"AutomatedATI_{version}{suffix}_{date_stamp}.pdf"

    out_path = os.path.join(ROOT_DIR, output_filename) if not os.path.isabs(output_filename) else output_filename

    pdf = ProjectPDF(doc_title=f"ATI V2 Codebase ({export_type.upper()})")
    pdf.set_auto_page_break(auto=True, margin=15)
    
    ignored_dirs = {'.git', '__pycache__', '.vscode', '.idea', 'venv'}
    print(f"Scanning codebase: {source_folder} [Export Mode: {export_type.upper()}]")

    primary_doc = []
    docs_and_images = []
    config_template_files = []
    py_files = []
    other_files = []
    log_files = []
    
    total_py_loc = 0
    total_files_count = 0

    for root, dirs, files in os.walk(source_folder):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]

        for filename in files:
            rel_path = os.path.relpath(os.path.join(root, filename), source_folder)

            # Exclude secrets and private runtime files; keep .env.example template
            if filename.startswith('.env') and filename != '.env.example':
                continue
            if filename.endswith(('.html', '.pdf', '.pyc')):
                continue 
            
            if 'data' in rel_path.split(os.sep):
                continue

            # Filtering based on export_type
            if export_type == "docs" and not filename.endswith(('.md', '.png', '.jpg', '.jpeg', '.txt')) and filename != '.env.example':
                continue
            elif export_type == "code" and not filename.endswith('.py') and filename != 'requirements.txt':
                continue
            elif export_type == "logs" and not filename.endswith('.log'):
                continue

            total_files_count += 1

            if os.path.basename(filename).lower() == 'documentation.md':
                primary_doc.append(rel_path)
            elif filename.endswith(('.md', '.png', '.jpg', '.jpeg')):
                docs_and_images.append(rel_path)
            elif filename == '.env.example':
                config_template_files.append(rel_path)
            elif filename.endswith('.py'):
                py_files.append(rel_path)
                if filename != 'x.py':
                    try:
                        with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as f:
                            total_py_loc += len(f.readlines())
                    except Exception:
                        pass
            elif filename.endswith('.log'):
                log_files.append(rel_path)
            else:
                other_files.append(rel_path)

    primary_doc.sort()
    docs_and_images.sort()
    config_template_files.sort()
    py_files.sort()
    other_files.sort()
    log_files.sort()
    
    ordered_files = primary_doc + docs_and_images + config_template_files + py_files + other_files + log_files
    links = {}

    # --- Header Page ---
    pdf.add_page()
    pdf.set_font("Courier", "B", 9)
    header_text = (
        "# ==============================================================================\n"
        "# Project: Automated CVE Threat Intel & OSINT Analyzer (ATI)\n"
        f"# Version: {version.upper()} | Export Scope: {export_type.upper()}\n"
        f"# Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# Python LOC: {total_py_loc} lines (excluding x.py)\n"
        f"# Total Files: {total_files_count} packaged files\n"
        "# Author: Created with love by Chiranjib and Team\n"
        "# ==============================================================================\n"
    )
    pdf.multi_cell(0, 4, header_text)
    pdf.ln(4)
    
    pdf.set_font("Courier", "B", 14)
    pdf.cell(0, 10, f"Project Codebase ({export_type.upper()} Export)", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)
    
    pdf.set_font("Courier", "", 9)
    raw_tree = generate_ascii_tree(source_folder, ignored_dirs)
    safe_tree = raw_tree.encode('latin-1', 'replace').decode('latin-1') 
    pdf.multi_cell(0, 4, safe_tree)
    
    # --- Index Page ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Table of Contents / Index", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "U", 10)
    pdf.set_text_color(0, 0, 255)
    
    for rel_path in ordered_files:
        link_id = pdf.add_link()
        links[rel_path] = link_id
        safe_path = rel_path.encode('latin-1', 'replace').decode('latin-1')
        pdf.cell(0, 8, safe_path, link=link_id, new_x="LMARGIN", new_y="NEXT")
        
    pdf.set_text_color(0, 0, 0)

    # --- File Content Pages ---
    for rel_path in ordered_files:
        file_path = os.path.join(source_folder, rel_path)
        pdf.add_page()
        
        if rel_path in links:
            pdf.set_link(links[rel_path])

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, f"FILE: {rel_path}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        try:
            if file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                pdf.image(file_path, w=pdf.epw)
                print(f"Added Image: {rel_path}")
                continue

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().splitlines()

            pdf.set_font("Helvetica", "I", 9)
            if not lines:
                pdf.cell(0, 5, "*[File is empty]*", new_x="LMARGIN", new_y="NEXT")
                continue

            if file_path.endswith('.log'):
                preview_count = min(30, len(lines))
                preview_lines = lines[-preview_count:]
                content = f"=== TRUNCATED LOG (Showing last {preview_count} of {len(lines)} lines) ===\n" + "\n".join(preview_lines)
                pdf.cell(0, 5, f"Log Total Lines: {len(lines)} (Displaying last {preview_count} lines)", new_x="LMARGIN", new_y="NEXT")
            else:
                content = "\n".join(lines)
                pdf.cell(0, 5, f"Line Count: {len(lines)}", new_x="LMARGIN", new_y="NEXT")

            pdf.ln(4)

            pdf.set_font("Courier", "", 8)
            safe_content = content.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 4, safe_content)
            print(f"Processed: {rel_path}")

        except Exception as e:
            pdf.set_text_color(255, 0, 0)
            pdf.cell(0, 5, f"[Error loading file: {e}]", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            print(f"Skipped {rel_path} due to error: {e}")

    pdf.output(out_path)
    print(f"\n[+] Successfully bundled codebase! Saved to: {out_path}")
    return os.path.basename(out_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bundle ATI project codebase into an indexed PDF documentation.")
    parser.add_argument("--source", "-s", type=str, default=ROOT_DIR, help="Source project folder (default: project root)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Custom output PDF filename")
    parser.add_argument("--version", "-v", type=str, default="v2", help="Project version tag (default: v2)")
    parser.add_argument("--type", "-t", type=str, default="full", choices=["full", "docs", "code", "logs", "report"],
                        help="Export type: 'full' (all), 'docs' (markdown only), 'code' (python source only), 'logs' (logs only), 'report' (threat intelligence dossier)")
    args = parser.parse_args()

    merge_project_files_to_pdf(source_folder=args.source, output_filename=args.output, version=args.version, export_type=args.type)
