# PDF Report Generator Module - Enhanced Version with Fixed Tables
# Creates detailed professional security reports

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable, Image
from reportlab.platypus.flowables import KeepTogether
from datetime import datetime
import os
import logging

class ReportGenerator:
    def __init__(self, reports_dir):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)
        self._create_styles()
        logging.basicConfig(level=logging.INFO)
    
    def _create_styles(self):
        self.styles = getSampleStyleSheet()
        
        # Main Title
        self.styles.add(ParagraphStyle(
            name='MainTitle',
            parent=self.styles['Heading1'],
            fontSize=25,
            spaceAfter=10,
            textColor=colors.HexColor('#1a2b3c'),
            alignment=1
        ))
        
        # Subtitle
        self.styles.add(ParagraphStyle(
            name='SubTitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=30,
            textColor=colors.HexColor('#4a627a'),
            alignment=1
        ))
        
        # Section Header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=18,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2c3e50')
        ))
        
        # Subsection
        self.styles.add(ParagraphStyle(
            name='Subsection',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.HexColor('#34495e')
        ))
        
        # Normal text
        self.styles.add(ParagraphStyle(
            name='NormalText',
            parent=self.styles['Normal'],
            fontSize=9,
            spaceAfter=4
        ))
        
        # Small text
        self.styles.add(ParagraphStyle(
            name='SmallText',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#7f8c8d')
        ))
        
        # Footer
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#95a5a6'),
            alignment=1
        ))
        
        # Alert styles
        self.styles.add(ParagraphStyle(
            name='AlertHigh',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#e74c3c'),
            fontSize=8,
            leftIndent=10,
            spaceAfter=4
        ))
        
        self.styles.add(ParagraphStyle(
            name='AlertMedium',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#f39c12'),
            fontSize=8,
            leftIndent=10,
            spaceAfter=4
        ))
        
        self.styles.add(ParagraphStyle(
            name='AlertLow',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#3498db'),
            fontSize=8,
            leftIndent=10,
            spaceAfter=4
        ))
        
        # Risk styles
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#e74c3c'),
            fontSize=8,
            leftIndent=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#f39c12'),
            fontSize=8,
            leftIndent=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#27ae60'),
            fontSize=8,
            leftIndent=10
        ))
    
    def _format_timestamp(self, timestamp):
        if not timestamp:
            return 'N/A'
        try:
            if 'T' in timestamp:
                return timestamp.split('T')[0] + ' ' + timestamp.split('T')[1][:8]
            return timestamp
        except:
            return timestamp
    
    def _truncate_text(self, text, max_length=80):
        """Truncate text to prevent overflow"""
        if not text:
            return ''
        text = str(text)
        if len(text) > max_length:
            return text[:max_length] + '...'
        return text
    
    def _get_risk_level(self, conn):
        port = conn.get('remote_port')
        process = conn.get('process', '').lower()
        
        if port in [4444, 1337, 31337]:
            return 'HIGH', 'Known backdoor port'
        elif port in [5555, 6666, 6667, 6668, 6669]:
            return 'MEDIUM', 'Suspicious port'
        elif process in ['powershell.exe', 'cmd.exe', 'wscript.exe', 'rundll32.exe']:
            return 'MEDIUM', f'Suspicious process {conn.get("process")}'
        elif conn.get('remote_ip') and not conn.get('remote_ip').startswith(('192.168.', '10.', '172.', '127.')):
            return 'LOW', f'External connection'
        return 'NORMAL', 'Local connection'
    
    def _get_cpu_status(self, percent):
        if percent >= 80:
            return "CRITICAL"
        elif percent >= 60:
            return "WARNING"
        elif percent >= 30:
            return "ELEVATED"
        else:
            return "NORMAL"
    
    def _get_memory_status(self, percent):
        if percent >= 80:
            return "CRITICAL"
        elif percent >= 60:
            return "WARNING"
        elif percent >= 30:
            return "ELEVATED"
        else:
            return "NORMAL"
    
    def generate_report(self, alerts, system_stats, logs_summary, connections=None, report_title=None):
        if not report_title:
            report_title = f"SIGMA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        filename = os.path.join(self.reports_dir, f"{report_title}.pdf")
        
        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=0.6 * inch,
            leftMargin=0.6 * inch,
            topMargin=0.6 * inch,
            bottomMargin=0.6 * inch
        )
        
        story = []
        
        # ========== COVER PAGE ==========
        story.append(Spacer(1, 2.2 * inch))
        story.append(Paragraph("SIGMA", self.styles['MainTitle']))
        story.append(Paragraph("Security Information Gathering & Monitoring System", self.styles['SubTitle']))
        story.append(Spacer(1, 0.8 * inch))
        story.append(Paragraph("Security Assessment Report", self.styles['SubTitle']))
        story.append(Spacer(1, 1.2 * inch))
        
        info_data = [
            ['Report ID:', report_title],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Analysis Period:', 'Last 24 Hours'],
            ['System:', 'Windows Workstation']
        ]
        
        info_table = Table(info_data, colWidths=[1.2 * inch, 4 * inch])
        info_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(info_table)
        story.append(PageBreak())
        
        # ========== 1. EXECUTIVE SUMMARY ==========
        story.append(Paragraph("1. Executive Summary", self.styles['SectionHeader']))
        
        story.append(Paragraph(
            "This report provides a comprehensive security assessment of the monitored Windows system. "
            "Key findings and actionable recommendations are highlighted below.",
            self.styles['SmallText']
        ))
        story.append(Spacer(1, 0.15 * inch))
        
        # Calculate statistics
        high_alerts = [a for a in alerts if a.get('severity') == 'HIGH']
        medium_alerts = [a for a in alerts if a.get('severity') == 'MEDIUM']
        low_alerts = [a for a in alerts if a.get('severity') == 'LOW']
        total_alerts = len(alerts)
        
        # Connection risk assessment
        high_risk_conns = []
        medium_risk_conns = []
        if connections:
            for conn in connections:
                threat, desc = self._get_risk_level(conn)
                if threat == 'HIGH':
                    high_risk_conns.append(conn)
                elif threat == 'MEDIUM':
                    medium_risk_conns.append(conn)
        
        # Summary metrics table - Fixed column widths
        summary_data = [
            ['Metric', 'Value', 'Status'],
            ['Total Security Alerts', str(total_alerts), '⚠️' if total_alerts > 0 else '✅'],
            ['HIGH Severity Alerts', str(len(high_alerts)), '🔴' if len(high_alerts) > 0 else '✅'],
            ['MEDIUM Severity Alerts', str(len(medium_alerts)), '🟠' if len(medium_alerts) > 0 else '✅'],
            ['LOW Severity Alerts', str(len(low_alerts)), '🔵' if len(low_alerts) > 0 else '✅'],
            ['Active Connections', str(len(connections) if connections else 0), 'ℹ️'],
            ['HIGH Risk Connections', str(len(high_risk_conns)), '🔴' if len(high_risk_conns) > 0 else '🟢'],
            ['MEDIUM Risk Connections', str(len(medium_risk_conns)), '🟠' if len(medium_risk_conns) > 0 else '🟢']
        ]
        
        summary_table = Table(summary_data, colWidths=[2.2 * inch, 1 * inch, 1.5 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fafafa')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        
        story.append(summary_table)
        
        # Critical findings
        if len(high_alerts) > 0 or len(high_risk_conns) > 0:
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph(
                "<b><font color='#e74c3c'> CRITICAL FINDINGS DETECTED</font></b>",
                self.styles['NormalText']
            ))
            if len(high_alerts) > 0:
                story.append(Paragraph(
                    f"• {len(high_alerts)} HIGH severity security alerts detected",
                    self.styles['AlertHigh']
                ))
            if len(high_risk_conns) > 0:
                story.append(Paragraph(
                    f"• {len(high_risk_conns)} HIGH risk network connections detected",
                    self.styles['RiskHigh']
                ))
        
        story.append(Spacer(1, 0.15 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
        
        # ========== 2. SYSTEM HEALTH ==========
        story.append(Paragraph("2. System Health", self.styles['SectionHeader']))
        
        story.append(Paragraph(
            "System health metrics provide insight into system performance and stability.",
            self.styles['SmallText']
        ))
        story.append(Spacer(1, 0.1 * inch))
        
        if system_stats:
            cpu = system_stats.get('cpu', {})
            mem = system_stats.get('memory', {})
            sys_info = system_stats.get('system', {})
            
            cpu_percent = cpu.get('percent', 0)
            mem_percent = mem.get('percent', 0)
            days = sys_info.get('uptime_days', 0)
            hours = sys_info.get('uptime_hours', 0)
            minutes = sys_info.get('uptime_minutes', 0)
            boot = sys_info.get('boot_time', 'Unknown')
            
            system_data = [
                ['Metric', 'Current Value', 'Status'],
                ['CPU Usage', f"{cpu_percent}%", self._get_cpu_status(cpu_percent)],
                ['Memory Usage', f"{mem_percent}%", self._get_memory_status(mem_percent)],
                ['Memory Used', f"{mem.get('used_gb', 0)} GB / {mem.get('total_gb', 0)} GB", ''],
                ['System Uptime', f"{days}d {hours}h {minutes}m", ''],
                ['Last Boot', self._truncate_text(boot, 30), '']
            ]
            
            system_table = Table(system_data, colWidths=[1.8 * inch, 1.8 * inch, 2 * inch])
            system_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fafafa')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            
            story.append(system_table)
        
        story.append(Spacer(1, 0.15 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
        
        # ========== 3. SECURITY ALERTS ==========
        story.append(Paragraph("3. Security Alerts", self.styles['SectionHeader']))
        
        story.append(Paragraph(
            "Security alerts are generated when the system detects activity matching known threat patterns.",
            self.styles['SmallText']
        ))
        story.append(Spacer(1, 0.1 * inch))
        
        if alerts:
            # Alert summary line
            story.append(Paragraph(f"Total: {total_alerts} | HIGH: {len(high_alerts)} | MEDIUM: {len(medium_alerts)} | LOW: {len(low_alerts)}", self.styles['NormalText']))
            story.append(Spacer(1, 0.1 * inch))
            
            # HIGH severity alerts - using list format instead of table
            if high_alerts:
                story.append(Paragraph("<b><font color='#e74c3c'> HIGH Severity Alerts</font></b>", self.styles['Subsection']))
                for alert in high_alerts[:10]:
                    timestamp = self._format_timestamp(alert.get('timestamp'))
                    rule_name = self._truncate_text(alert.get('rule_name', 'Unknown'), 50)
                    details = self._truncate_text(alert.get('details', 'No details'), 100)
                    story.append(Paragraph(
                        f"• <b>{rule_name}</b><br/>"
                        f"  Time: {timestamp}<br/>"
                        f"  {details}",
                        self.styles['AlertHigh']
                    ))
                    story.append(Spacer(1, 0.05 * inch))
            
            # MEDIUM severity alerts
            if medium_alerts:
                if high_alerts:
                    story.append(Spacer(1, 0.1 * inch))
                story.append(Paragraph("<b><font color='#f39c12'> MEDIUM Severity Alerts</font></b>", self.styles['Subsection']))
                for alert in medium_alerts[:10]:
                    timestamp = self._format_timestamp(alert.get('timestamp'))
                    rule_name = self._truncate_text(alert.get('rule_name', 'Unknown'), 50)
                    details = self._truncate_text(alert.get('details', 'No details'), 100)
                    story.append(Paragraph(
                        f"• <b>{rule_name}</b><br/>"
                        f"  Time: {timestamp}<br/>"
                        f"  {details}",
                        self.styles['AlertMedium']
                    ))
                    story.append(Spacer(1, 0.05 * inch))
            
            if len(alerts) > 20:
                story.append(Paragraph(f"Plus {len(alerts) - 20} additional alerts not shown", self.styles['SmallText']))
        else:
            story.append(Paragraph("No security alerts detected during the monitoring period.", self.styles['NormalText']))
        
        story.append(Spacer(1, 0.15 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
        
        # ========== 4. NETWORK CONNECTIONS ==========
        if connections and len(connections) > 0:
            story.append(Paragraph("4. Network Connections", self.styles['SectionHeader']))
            
            story.append(Paragraph(
                "Network connections are analyzed for potential security risks.",
                self.styles['SmallText']
            ))
            story.append(Spacer(1, 0.1 * inch))
            
            # Network statistics
            tcp_count = len([c for c in connections if c.get('type') == 'TCP'])
            udp_count = len([c for c in connections if c.get('type') == 'UDP'])
            established = len([c for c in connections if c.get('status') == 'ESTABLISHED'])
            listening = len([c for c in connections if c.get('status') == 'LISTEN'])
            
            story.append(Paragraph(f"Total: {len(connections)} | TCP: {tcp_count} | UDP: {udp_count} | Established: {established} | Listening: {listening}", self.styles['NormalText']))
            story.append(Spacer(1, 0.1 * inch))
            
            # HIGH RISK connections
            if high_risk_conns:
                story.append(Paragraph("<b><font color='#e74c3c'> HIGH RISK Connections</font></b>", self.styles['Subsection']))
                for conn in high_risk_conns[:8]:
                    process = self._truncate_text(conn.get('process', 'Unknown'), 30)
                    remote = f"{conn.get('remote_ip', 'N/A')}:{conn.get('remote_port', 'N/A')}"
                    story.append(Paragraph(
                        f"• <b>{process}</b> → {remote}<br/>"
                        f"  Status: {conn.get('status', 'N/A')}",
                        self.styles['RiskHigh']
                    ))
                    story.append(Spacer(1, 0.05 * inch))
            
            # MEDIUM RISK connections
            if medium_risk_conns:
                if high_risk_conns:
                    story.append(Spacer(1, 0.1 * inch))
                story.append(Paragraph("<b><font color='#f39c12'>MEDIUM RISK Connections</font></b>", self.styles['Subsection']))
                for conn in medium_risk_conns[:8]:
                    process = self._truncate_text(conn.get('process', 'Unknown'), 30)
                    remote = f"{conn.get('remote_ip', 'N/A')}:{conn.get('remote_port', 'N/A')}"
                    story.append(Paragraph(
                        f"• <b>{process}</b> → {remote}<br/>"
                        f"  Status: {conn.get('status', 'N/A')}",
                        self.styles['RiskMedium']
                    ))
                    story.append(Spacer(1, 0.05 * inch))
            
            # Risk summary table
            story.append(Spacer(1, 0.1 * inch))
            risk_summary = [
                ['Risk Level', 'Count', 'Action'],
                ['HIGH RISK', str(len(high_risk_conns)), 'Immediate investigation'],
                ['MEDIUM RISK', str(len(medium_risk_conns)), 'Review and monitor'],
                ['LOW/NORMAL', str(len(connections) - len(high_risk_conns) - len(medium_risk_conns)), 'No action required']
            ]
            
            risk_table = Table(risk_summary, colWidths=[1.5 * inch, 1 * inch, 2.5 * inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fafafa')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            
            story.append(risk_table)
            story.append(Spacer(1, 0.15 * inch))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
        
        # ========== 5. EVENT LOG SUMMARY ==========
        story.append(Paragraph("5. Event Log Summary", self.styles['SectionHeader']))
        
        if logs_summary:
            log_data = [['Log Type', 'Events', 'Description']]
            log_descriptions = {
                'Security': 'Authentication and audit events',
                'System': 'System component events',
                'Application': 'Application events'
            }
            
            for log_type, count in logs_summary.items():
                desc = log_descriptions.get(log_type, 'System events')
                log_data.append([log_type, str(count), desc])
            
            log_table = Table(log_data, colWidths=[1.2 * inch, 0.8 * inch, 3.5 * inch])
            log_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fafafa')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            
            story.append(log_table)
        else:
            story.append(Paragraph("No log data available.", self.styles['NormalText']))
        
        story.append(Spacer(1, 0.15 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
        
        # ========== 6. RECOMMENDATIONS ==========
        story.append(Paragraph("6. Recommendations", self.styles['SectionHeader']))
        
        story.append(Paragraph(
            "Based on the findings, the following actions are recommended:",
            self.styles['SmallText']
        ))
        story.append(Spacer(1, 0.1 * inch))
        
        recommendations = []
        
        if len(high_alerts) > 0:
            recommendations.append(f"Investigate {len(high_alerts)} HIGH severity alerts immediately")
        if len(high_risk_conns) > 0:
            recommendations.append(f"Block {len(high_risk_conns)} HIGH risk IP addresses at the firewall")
        if len(medium_alerts) > 0:
            recommendations.append(f"Review {len(medium_alerts)} MEDIUM severity alerts")
        if len(medium_risk_conns) > 0:
            recommendations.append(f"Monitor {len(medium_risk_conns)} MEDIUM risk connections")
        
        recommendations.append("Keep Windows and security tools updated")
        recommendations.append("Review security logs regularly")
        recommendations.append("Enable multi-factor authentication for critical accounts")
        recommendations.append("Schedule regular vulnerability scans")
        
        # Remove duplicates
        seen = set()
        unique_recs = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recs.append(rec)
        
        for i, rec in enumerate(unique_recs[:10], 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['NormalText']))
            story.append(Spacer(1, 0.05 * inch))
        
        story.append(Spacer(1, 0.2 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc')))
        
        # ========== FOOTER ==========
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(
            f"SIGMA Security Report | Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['Footer']
        ))
        
        doc.build(story)
        logging.info(f"Report generated: {filename}")
        return filename
    
    def generate_quick_report(self, alerts, system_stats, connections=None):
        """Generate a quick summary report"""
        filename = os.path.join(self.reports_dir, f"Quick_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        story = []
        
        story.append(Paragraph("SIGMA", self.styles['MainTitle']))
        story.append(Paragraph("Security Information Gathering & Monitoring System", self.styles['SubTitle']))
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("Quick Security Summary", self.styles['Subsection']))
        story.append(Spacer(1, 0.2 * inch))
        
        high_count = len([a for a in alerts if a.get('severity') == 'HIGH'])
        story.append(Paragraph(f"Total Alerts: {len(alerts)}", self.styles['NormalText']))
        story.append(Paragraph(f"HIGH Severity: {high_count}", self.styles['AlertHigh']))
        
        if connections:
            high_risk = 0
            for conn in connections:
                threat, _ = self._get_risk_level(conn)
                if threat == 'HIGH':
                    high_risk += 1
            story.append(Paragraph(f"HIGH Risk Connections: {high_risk}", self.styles['RiskHigh']))
        
        story.append(Spacer(1, 0.2 * inch))
        
        if system_stats:
            cpu = system_stats.get('cpu', {}).get('percent', 0)
            mem = system_stats.get('memory', {}).get('percent', 0)
            uptime = system_stats.get('system', {})
            days = uptime.get('uptime_days', 0)
            story.append(Paragraph(f"CPU: {cpu}% | Memory: {mem}% | Uptime: {days} days", self.styles['NormalText']))
        
        if alerts:
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph("Recent Alerts:", self.styles['Subsection']))
            for alert in alerts[:5]:
                story.append(Paragraph(f"• {alert.get('rule_name')} ({alert.get('severity')})", self.styles['NormalText']))
        
        doc.build(story)
        return filename