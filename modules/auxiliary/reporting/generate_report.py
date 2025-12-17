#!/usr/bin/env python3
"""
Report Generator
================

Comprehensive reporting module for generating security assessment reports
in multiple formats (HTML, PDF, JSON, XML).

Author: Brainless Security Team
Module: auxiliary/reporting/generate_report
Type: auxiliary
Rank: excellent
"""

import os
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Report Generator"
DESCRIPTION = "Comprehensive reporting module for security assessment results"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class ReportGenerator(LoggerMixin):
    """
    Comprehensive report generation module
    """
    
    def __init__(self):
        super().__init__('ReportGenerator')
        self.data = {}
        self.output_format = 'html'
        self.output_file = None
        self.template_dir = './templates'
        self.include_recommendations = True
        self.include_executive_summary = True
        
        # Report sections
        self.sections = [
            'executive_summary',
            'methodology',
            'findings',
            'risk_assessment',
            'recommendations',
            'technical_details',
            'appendices'
        ]
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'data':
            self.data = json.loads(value)
        elif option.lower() == 'output_format':
            self.output_format = value.lower()
        elif option.lower() == 'output_file':
            self.output_file = value
        elif option.lower() == 'include_recommendations':
            self.include_recommendations = value.lower() == 'true'
        elif option.lower() == 'include_executive_summary':
            self.include_executive_summary = value.lower() == 'true'
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'DATA': {'description': 'JSON data to include in report', 'required': True, 'default': '{}'},
            'OUTPUT_FORMAT': {'description': 'Output format (html, pdf, json, xml)', 'required': False, 'default': 'html'},
            'OUTPUT_FILE': {'description': 'Output file path', 'required': False, 'default': 'report.html'},
            'INCLUDE_RECOMMENDATIONS': {'description': 'Include recommendations section', 'required': False, 'default': 'true'},
            'INCLUDE_EXECUTIVE_SUMMARY': {'description': 'Include executive summary', 'required': False, 'default': 'true'}
        }
    
    def load_sample_data(self) -> dict:
        """
        Load sample assessment data for demonstration
        """
        return {
            'assessment_info': {
                'title': 'Security Assessment Report',
                'client': 'Example Corporation',
                'assessment_date': '2025-12-17',
                'assessor': 'Brainless Security Team',
                'scope': 'Internal network penetration test',
                'duration': '5 days'
            },
            'executive_summary': {
                'risk_level': 'Medium',
                'total_findings': 15,
                'critical_findings': 2,
                'high_findings': 4,
                'medium_findings': 6,
                'low_findings': 3,
                'summary': 'The assessment identified several security vulnerabilities that require attention. While no critical vulnerabilities were found that could lead to immediate compromise, the accumulation of medium and high severity issues presents a significant risk to the organization.'
            },
            'findings': [
                {
                    'id': 'F001',
                    'title': 'Weak Password Policy',
                    'severity': 'High',
                    'cvss_score': 7.5,
                    'description': 'The organization uses weak password policies allowing easily guessable passwords.',
                    'impact': 'Attackers can easily guess user passwords and gain unauthorized access.',
                    'likelihood': 'High',
                    'recommendation': 'Implement strong password policy with minimum 12 characters, complexity requirements, and regular rotation.',
                    'status': 'Open'
                },
                {
                    'id': 'F002',
                    'title': 'Outdated Software',
                    'severity': 'Medium',
                    'cvss_score': 5.3,
                    'description': 'Several systems are running outdated software with known vulnerabilities.',
                    'impact': 'Exploitable vulnerabilities could allow attackers to compromise systems.',
                    'likelihood': 'Medium',
                    'recommendation': 'Implement regular patch management process and update all systems.',
                    'status': 'Open'
                },
                {
                    'id': 'F003',
                    'title': 'Open Ports',
                    'severity': 'Low',
                    'cvss_score': 3.1,
                    'description': 'Unnecessary services are exposed on the network.',
                    'impact': 'Increases attack surface and potential entry points.',
                    'likelihood': 'Low',
                    'recommendation': 'Close unnecessary ports and disable unused services.',
                    'status': 'Open'
                }
            ],
            'methodology': {
                'phases': [
                    'Reconnaissance',
                    'Scanning',
                    'Exploitation',
                    'Post-exploitation',
                    'Reporting'
                ],
                'tools': [
                    'Nmap',
                    'Metasploit',
                    'Wireshark',
                    'Burp Suite'
                ]
            }
        }
    
    def generate_html_report(self) -> str:
        """
        Generate HTML report
        """
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{self.data['assessment_info']['title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #2980b9; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ border: 1px solid #bdc3c7; padding: 15px; margin: 15px 0; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #e67e22; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #2ecc71; }}
        .info {{ border-left: 5px solid #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; color: #7f8c8d; }}
        .risk-score {{ font-size: 24px; font-weight: bold; }}
        .risk-critical {{ color: #e74c3c; }}
        .risk-high {{ color: #e67e22; }}
        .risk-medium {{ color: #f1c40f; }}
        .risk-low {{ color: #2ecc71; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{self.data['assessment_info']['title']}</h1>
        
        <div class="summary">
            <h2>Assessment Information</h2>
            <p><strong>Client:</strong> {self.data['assessment_info']['client']}</p>
            <p><strong>Assessment Date:</strong> {self.data['assessment_info']['assessment_date']}</p>
            <p><strong>Assessor:</strong> {self.data['assessment_info']['assessor']}</p>
            <p><strong>Scope:</strong> {self.data['assessment_info']['scope']}</p>
            <p><strong>Duration:</strong> {self.data['assessment_info']['duration']}</p>
        </div>
        
        {self.generate_executive_summary_html() if self.include_executive_summary else ''}
        
        <h2>Findings</h2>
        {self.generate_findings_html()}
        
        <h2>Methodology</h2>
        {self.generate_methodology_html()}
        
        {self.generate_recommendations_html() if self.include_recommendations else ''}
        
        <div class="footer">
            <p><strong>Confidentiality Notice:</strong> This report contains sensitive information and should be handled accordingly.</p>
            <p>Generated by Brainless Framework on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
        return html_template
    
    def generate_executive_summary_html(self) -> str:
        """
        Generate executive summary section
        """
        summary = self.data['executive_summary']
        
        risk_class = ''
        if summary['risk_level'] == 'Critical':
            risk_class = 'risk-critical'
        elif summary['risk_level'] == 'High':
            risk_class = 'risk-high'
        elif summary['risk_level'] == 'Medium':
            risk_class = 'risk-medium'
        else:
            risk_class = 'risk-low'
        
        return f"""
        <h2>Executive Summary</h2>
        <div class="summary">
            <p class="risk-score {risk_class}">Risk Level: {summary['risk_level']}</p>
            <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
            <p><strong>Critical:</strong> {summary['critical_findings']} | 
               <strong>High:</strong> {summary['high_findings']} | 
               <strong>Medium:</strong> {summary['medium_findings']} | 
               <strong>Low:</strong> {summary['low_findings']}</p>
            <p>{summary['summary']}</p>
        </div>
        """
    
    def generate_findings_html(self) -> str:
        """
        Generate findings section
        """
        findings_html = ""
        
        for finding in self.data['findings']:
            severity_class = finding['severity'].lower()
            
            findings_html += f"""
            <div class="finding {severity_class}">
                <h3>{finding['id']} - {finding['title']}</h3>
                <p><strong>Severity:</strong> <span class="{severity_class}">{finding['severity']}</span></p>
                <p><strong>CVSS Score:</strong> {finding['cvss_score']}</p>
                <p><strong>Description:</strong> {finding['description']}</p>
                <p><strong>Impact:</strong> {finding['impact']}</p>
                <p><strong>Likelihood:</strong> {finding['likelihood']}</p>
                <p><strong>Status:</strong> {finding['status']}</p>
            </div>
            """
        
        return findings_html
    
    def generate_methodology_html(self) -> str:
        """
        Generate methodology section
        """
        methodology = self.data['methodology']
        
        phases_html = ""
        for phase in methodology['phases']:
            phases_html += f"<li>{phase}</li>"
        
        tools_html = ""
        for tool in methodology['tools']:
            tools_html += f"<li>{tool}</li>"
        
        return f"""
        <div class="summary">
            <h3>Assessment Phases</h3>
            <ul>
                {phases_html}
            </ul>
            <h3>Tools Used</h3>
            <ul>
                {tools_html}
            </ul>
        </div>
        """
    
    def generate_recommendations_html(self) -> str:
        """
        Generate recommendations section
        """
        recommendations_html = "<h2>Recommendations</h2>"
        
        for finding in self.data['findings']:
            if finding.get('recommendation'):
                recommendations_html += f"""
                <div class="finding">
                    <h3>{finding['id']} - {finding['title']}</h3>
                    <p><strong>Recommendation:</strong> {finding['recommendation']}</p>
                </div>
                """
        
        return recommendations_html
    
    def generate_json_report(self) -> str:
        """
        Generate JSON report
        """
        return json.dumps(self.data, indent=2, default=str)
    
    def generate_xml_report(self) -> str:
        """
        Generate XML report
        """
        root = ET.Element("security_assessment_report")
        
        # Assessment info
        assessment_info = ET.SubElement(root, "assessment_info")
        for key, value in self.data['assessment_info'].items():
            elem = ET.SubElement(assessment_info, key)
            elem.text = str(value)
        
        # Executive summary
        if 'executive_summary' in self.data and self.include_executive_summary:
            exec_summary = ET.SubElement(root, "executive_summary")
            for key, value in self.data['executive_summary'].items():
                elem = ET.SubElement(exec_summary, key)
                elem.text = str(value)
        
        # Findings
        findings = ET.SubElement(root, "findings")
        for finding in self.data['findings']:
            finding_elem = ET.SubElement(findings, "finding")
            for key, value in finding.items():
                elem = ET.SubElement(finding_elem, key)
                elem.text = str(value)
        
        # Methodology
        methodology = ET.SubElement(root, "methodology")
        phases = ET.SubElement(methodology, "phases")
        for phase in self.data['methodology']['phases']:
            phase_elem = ET.SubElement(phases, "phase")
            phase_elem.text = phase
        
        tools = ET.SubElement(methodology, "tools")
        for tool in self.data['methodology']['tools']:
            tool_elem = ET.SubElement(tools, "tool")
            tool_elem.text = tool
        
        # Convert to string
        return ET.tostring(root, encoding='unicode', method='xml')
    
    def save_report(self, content: str):
        """
        Save report to file
        """
        if not self.output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.output_file = f"security_report_{timestamp}.{self.output_format}"
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.info(f"Report saved to: {self.output_file}")
            return True
            
        except Exception as e:
            self.error(f"Failed to save report: {e}")
            return False
    
    def generate_report(self) -> dict:
        """
        Generate the complete report
        """
        if not self.data:
            # Load sample data if none provided
            self.data = self.load_sample_data()
            self.info("Using sample data for demonstration")
        
        try:
            self.info(f"Generating {self.output_format.upper()} report...")
            
            if self.output_format == 'html':
                content = self.generate_html_report()
            elif self.output_format == 'json':
                content = self.generate_json_report()
            elif self.output_format == 'xml':
                content = self.generate_xml_report()
            else:
                return {'success': False, 'message': f'Unsupported format: {self.output_format}'}
            
            # Save report
            if self.save_report(content):
                summary = {
                    'format': self.output_format,
                    'output_file': self.output_file,
                    'findings_count': len(self.data.get('findings', [])),
                    'assessment_title': self.data['assessment_info'].get('title', 'Security Assessment')
                }
                
                return {'success': True, 'summary': summary}
            else:
                return {'success': False, 'message': 'Failed to save report'}
            
        except Exception as e:
            self.error(f"Report generation failed: {e}")
            return {'success': False, 'message': f'Generation failed: {str(e)}'}
    
    def run(self) -> dict:
        """
        Main module execution
        """
        return self.generate_report()


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    generator = ReportGenerator()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            generator.set_option(key, value)
    
    return generator.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'DATA': '{}',
        'OUTPUT_FORMAT': 'html',
        'OUTPUT_FILE': 'report.html',
        'INCLUDE_RECOMMENDATIONS': 'true',
        'INCLUDE_EXECUTIVE_SUMMARY': 'true'
    }
    
    result = run(options)
    print(result)