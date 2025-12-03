"""
PDF Generator para HybridSecScan
Genera reportes profesionales con vulnerabilidades detectadas
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
from io import BytesIO
import os

# Colores profesionales para HybridSecScan
COLORS = {
    'primary': HexColor('#667eea'),
    'secondary': HexColor('#764ba2'),
    'critical': HexColor('#ff4444'),
    'high': HexColor('#ff9800'),
    'medium': HexColor('#ffc107'),
    'low': HexColor('#4caf50'),
    'white': white,
    'black': black,
    'light_gray': HexColor('#f5f5f5'),
    'dark_gray': HexColor('#333333')
}

def get_severity_color(severity):
    """Retorna color según nivel de severidad"""
    severity_lower = severity.lower()
    if severity_lower == 'critical':
        return COLORS['critical']
    elif severity_lower == 'high':
        return COLORS['high']
    elif severity_lower == 'medium':
        return COLORS['medium']
    else:
        return COLORS['low']

def generate_pdf_report(scan_data):
    """
    Genera un PDF profesional con los resultados del escaneo
    
    Args:
        scan_data: Dict con:
            - scan_type: 'sast' o 'dast'
            - target: archivo o URL escaneada
            - vulnerabilities: lista de vulnerabilidades
            - summary: stats del escaneo
            - timestamp: cuando se ejecutó
    
    Returns:
        bytes: Contenido del PDF
    """
    
    # Crear buffer en memoria
    buffer = BytesIO()
    
    # Configurar documento
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
        title="HybridSecScan Report"
    )
    
    # Estilos personalizados
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=COLORS['primary'],
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=COLORS['secondary'],
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold',
        borderPadding=10,
        borderColor=COLORS['primary'],
        borderWidth=1
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=COLORS['dark_gray'],
        spaceAfter=6
    )
    
    # Contenido del documento
    story = []
    
    # Header
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("🔐 HYBRIDSCAN SECURITY AUDIT REPORT", title_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Información del escaneo
    scan_type = scan_data.get('scan_type', 'unknown').upper()
    target = scan_data.get('target', 'N/A')
    timestamp = scan_data.get('timestamp', datetime.now().isoformat())
    
    info_data = [
        ['REPORT INFORMATION', ''],
        ['Scan Type:', scan_type],
        ['Target:', target],
        ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Timestamp:', timestamp],
    ]
    
    info_table = Table(info_data, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), COLORS['primary']),
        ('TEXTCOLOR', (0, 0), (1, 0), COLORS['white']),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (0, -1), COLORS['light_gray']),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, COLORS['dark_gray']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['white'], COLORS['light_gray']]),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    
    story.append(info_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Resumen de resultados
    summary = scan_data.get('summary', {})
    story.append(Paragraph("VULNERABILITY SUMMARY", heading2_style))
    
    summary_data = [
        ['Metric', 'Count', 'Percentage'],
    ]
    
    total_vuln = sum(int(summary.get(k, 0)) for k in ['critical', 'high', 'medium', 'low'] if isinstance(summary.get(k), (int, str)))
    
    if 'critical' in summary:
        pct = (int(summary['critical']) / total_vuln * 100) if total_vuln > 0 else 0
        summary_data.append(['🔴 CRITICAL', str(summary['critical']), f'{pct:.1f}%'])
    
    if 'high' in summary:
        pct = (int(summary['high']) / total_vuln * 100) if total_vuln > 0 else 0
        summary_data.append(['🟠 HIGH', str(summary['high']), f'{pct:.1f}%'])
    
    if 'medium' in summary:
        pct = (int(summary['medium']) / total_vuln * 100) if total_vuln > 0 else 0
        summary_data.append(['🟡 MEDIUM', str(summary['medium']), f'{pct:.1f}%'])
    
    if 'low' in summary:
        pct = (int(summary['low']) / total_vuln * 100) if total_vuln > 0 else 0
        summary_data.append(['🟢 LOW', str(summary['low']), f'{pct:.1f}%'])
    
    summary_data.append(['TOTAL', str(total_vuln), '100%'])
    
    summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
        ('TEXTCOLOR', (0, 0), (-1, 0), COLORS['white']),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, COLORS['dark_gray']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [COLORS['white'], COLORS['light_gray']]),
        ('BACKGROUND', (0, -1), (-1, -1), COLORS['secondary']),
        ('TEXTCOLOR', (0, -1), (-1, -1), COLORS['white']),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))
    
    # SECCIÓN ESPECIAL: Métricas híbridas (si aplica)
    if scan_type == 'HYBRID' and 'hybrid_metrics' in scan_data:
        metrics = scan_data['hybrid_metrics']
        story.append(Paragraph("HYBRID CORRELATION METRICS", heading2_style))
        
        metrics_data = [
            ['Metric', 'Value'],
            ['Total SAST Findings', str(metrics.get('total_sast', 0))],
            ['Total DAST Findings', str(metrics.get('total_dast', 0))],
            ['False Positive Reduction', f"{metrics.get('fp_reduction', 0):.1f}%"],
        ]
        
        metrics_table = Table(metrics_data, colWidths=[3*inch, 2*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['secondary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), COLORS['white']),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, COLORS['dark_gray']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['white'], COLORS['light_gray']]),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 0.3*inch))
    
    # Vulnerabilidades detalladas
    vulnerabilities = scan_data.get('vulnerabilities', [])
    correlations = scan_data.get('correlations', [])
    
    # CASO HÍBRIDO: Mostrar correlaciones
    if scan_type == 'HYBRID' and correlations:
        story.append(Paragraph("CORRELATED VULNERABILITIES", heading2_style))
        
        for i, corr in enumerate(correlations, 1):
            sast_vuln = corr.get('sast_vulnerability', {})
            dast_vuln = corr.get('dast_vulnerability', {})
            confidence = corr.get('confidence_score', 0) * 100
            
            # Determinar color de confianza
            if confidence >= 70:
                conf_color = COLORS['low'].hexval()  # Verde para alta confianza
            elif confidence >= 40:
                conf_color = COLORS['medium'].hexval()  # Amarillo para media
            else:
                conf_color = COLORS['high'].hexval()  # Naranja para baja
            
            corr_header = f"<b>{i}. Correlation #{i}</b> [<font color='#{conf_color}'>Confidence: {confidence:.1f}%</font>]"
            story.append(Paragraph(corr_header, normal_style))
            
            # SAST info
            sast_type = sast_vuln.get('type', 'Unknown')
            sast_file = sast_vuln.get('file', 'N/A')
            sast_line = sast_vuln.get('line', 0)
            story.append(Paragraph(f"<b>SAST Finding:</b> {sast_type} in {sast_file}:{sast_line}", normal_style))
            
            # DAST info
            dast_type = dast_vuln.get('type', 'Unknown')
            dast_endpoint = dast_vuln.get('endpoint', 'N/A')
            story.append(Paragraph(f"<b>DAST Finding:</b> {dast_type} at {dast_endpoint}", normal_style))
            
            # Explanation
            explanation = corr.get('explanation', 'These vulnerabilities share common characteristics suggesting they may be related.')
            story.append(Paragraph(f"<i>Analysis:</i> {explanation}", normal_style))
            
            story.append(Spacer(1, 0.15*inch))
        
        story.append(Spacer(1, 0.2*inch))
        
    # CASO NORMAL: Vulnerabilidades individuales
    elif vulnerabilities:
        story.append(Paragraph("DETAILED FINDINGS", heading2_style))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            # Identificar si es SAST o DAST (para reportes híbridos)
            source_label = ""
            if vuln.get('source'):
                source = vuln['source']
                source_color = COLORS['primary'].hexval() if source == 'SAST' else COLORS['secondary'].hexval()
                source_label = f" <font color='#{source_color}'>[{source}]</font>"
            
            # Prefer explicit 'title', fallback to 'type' (DAST) or 'name'
            raw_title = vuln.get('title') or vuln.get('type') or vuln.get('name') or 'Unknown Vulnerability'
            vuln_title = f"{i}. {raw_title}{source_label}"

            # Severity normalization
            severity = str(vuln.get('severity') or 'low').upper()

            # Párrafo con título y severidad
            severity_color = get_severity_color(severity)
            # severity_color.hexval() returns a hex string without '#'
            vuln_header = f"<b>{vuln_title}</b> [<font color='#{severity_color.hexval()}'>{severity}</font>]"
            story.append(Paragraph(vuln_header, normal_style))

            # Descripción: usar 'description' si existe, sino 'evidence', sino mensaje por defecto
            description = vuln.get('description') or vuln.get('evidence') or vuln.get('message') or 'No description available'
            story.append(Paragraph(f"<i>Description:</i> {description}", normal_style))

            # File y line (para SAST)
            if vuln.get('file'):
                file_line = f"{vuln['file']}"
                if vuln.get('line'):
                    file_line += f":{vuln['line']}"
                story.append(Paragraph(f"<i>Location:</i> {file_line}", normal_style))

            # URL and parameter if available (useful for DAST findings)
            if vuln.get('url'):
                story.append(Paragraph(f"<i>URL:</i> {vuln.get('url')}", normal_style))

            if vuln.get('parameter'):
                story.append(Paragraph(f"<i>Parameter:</i> {vuln.get('parameter')}", normal_style))

            if vuln.get('cwe') and str(vuln.get('cwe')).strip():
                story.append(Paragraph(f"<i>CWE:</i> {vuln['cwe']}", normal_style))

            # Remediation (SAST) o Solution (DAST)
            remediation = vuln.get('recommendation') or vuln.get('solution')
            if remediation and str(remediation).strip():
                story.append(Paragraph(f"<i>Remediation:</i> {remediation}", normal_style))

            if vuln.get('cvss_score'):
                story.append(Paragraph(f"<i>CVSS Score:</i> {vuln['cvss_score']}", normal_style))

            # Mostrar herramienta que lo detectó
            if vuln.get('tool'):
                story.append(Paragraph(f"<i>Detected by:</i> {vuln['tool']}", normal_style))

            story.append(Spacer(1, 0.1*inch))
        
        story.append(Spacer(1, 0.2*inch))
    
    # Footer
    story.append(Spacer(1, 0.3*inch))
    footer_text = "This report is confidential and contains information about security vulnerabilities. " \
                  "Please treat this document with appropriate confidentiality measures."
    story.append(Paragraph(footer_text, ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=COLORS['dark_gray'],
        alignment=TA_CENTER,
        fontName='Helvetica-Oblique'
    )))
    
    story.append(Spacer(1, 0.1*inch))
    generated_text = f"Generated by HybridSecScan on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(generated_text, ParagraphStyle(
        'Generated',
        parent=styles['Normal'],
        fontSize=8,
        textColor=COLORS['primary'],
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )))
    
    # Build PDF
    doc.build(story)
    
    # Obtener bytes
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return pdf_bytes

def generate_json_summary(scan_data):
    """Genera un resumen JSON del escaneo para análisis"""
    return {
        'scan_type': scan_data.get('scan_type'),
        'target': scan_data.get('target'),
        'timestamp': scan_data.get('timestamp'),
        'summary': scan_data.get('summary', {}),
        'vulnerabilities_count': len(scan_data.get('vulnerabilities', [])),
        'severity_distribution': {
            'critical': sum(1 for v in scan_data.get('vulnerabilities', []) if v.get('severity', '').lower() == 'critical'),
            'high': sum(1 for v in scan_data.get('vulnerabilities', []) if v.get('severity', '').lower() == 'high'),
            'medium': sum(1 for v in scan_data.get('vulnerabilities', []) if v.get('severity', '').lower() == 'medium'),
            'low': sum(1 for v in scan_data.get('vulnerabilities', []) if v.get('severity', '').lower() == 'low'),
        }
    }
