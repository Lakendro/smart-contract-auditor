"""
HTML报告生成器
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict


class HTMLReporter:
    """HTML格式报告生成器"""

    def generate(self, results: Dict, output_path: Path):
        """生成HTML报告"""
        html_content = self._generate_html(results)
        output_path.write_text(html_content, encoding='utf-8')

    def _generate_html(self, results: Dict) -> str:
        """生成HTML内容"""
        # 统计问题
        total_findings = self._count_findings(results)
        severity_breakdown = self._get_severity_breakdown(results)

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>智能合约审计报告</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}

        .summary {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}

        .summary h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}

        .stat-card .label {{
            color: #666;
            margin-top: 5px;
        }}

        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}

        .section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}

        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}

        .finding {{
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 0 8px 8px 0;
        }}

        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
        }}

        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}

        .finding-meta {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}

        .code-block {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}

        .recommendation {{
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 4px solid #2196f3;
        }}

        .recommendation strong {{
            color: #1976d2;
        }}

        .remediation-section {{
            margin-top: 30px;
        }}

        .remediation-item {{
            background: #fff3e0;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #ff9800;
        }}

        .remediation-item h3 {{
            color: #e65100;
            margin-bottom: 10px;
        }}

        .solution-list {{
            margin-left: 20px;
            margin-top: 10px;
        }}

        .solution-list li {{
            margin: 8px 0;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ 智能合约审计报告</h1>
            <p class="subtitle">Smart Contract Security Audit Report</p>
            <p style="margin-top: 20px;">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="summary">
            <h2>📊 审计摘要</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number">{total_findings['total']}</div>
                    <div class="label">总问题数</div>
                </div>
                <div class="stat-card">
                    <div class="number severity-critical">{severity_breakdown.get('critical', 0)}</div>
                    <div class="label">严重</div>
                </div>
                <div class="stat-card">
                    <div class="number severity-high">{severity_breakdown.get('high', 0)}</div>
                    <div class="label">高危</div>
                </div>
                <div class="stat-card">
                    <div class="number severity-medium">{severity_breakdown.get('medium', 0)}</div>
                    <div class="label">中危</div>
                </div>
                <div class="stat-card">
                    <div class="number severity-low">{severity_breakdown.get('low', 0)}</div>
                    <div class="label">低危</div>
                </div>
            </div>
        </div>

        {self._generate_findings_section(results)}

        {self._generate_remediation_section(results)}

        <footer>
            <p>由 Smart Contract Auditor 自动生成</p>
            <p>建议: 请仔细审查所有发现的问题，并在部署前进行修复</p>
        </footer>
    </div>
</body>
</html>"""
        return html

    def _count_findings(self, results: Dict) -> Dict:
        """统计问题数量"""
        counts = {
            'slither': 0,
            'custom': 0,
            'total': 0
        }

        for category in ['slither', 'custom']:
            if category in results:
                for detector_name, findings in results[category].items():
                    counts[category] += len(findings)
                    counts['total'] += len(findings)

        return counts

    def _get_severity_breakdown(self, results: Dict) -> Dict:
        """获取严重程度分布"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for category in ['slither', 'custom']:
            if category in results:
                for detector_name, findings in results[category].items():
                    for finding in findings:
                        severity = finding.get('severity', 'Medium').lower()
                        if severity in breakdown:
                            breakdown[severity] += 1

        return breakdown

    def _generate_findings_section(self, results: Dict) -> str:
        """生成发现的问题部分"""
        sections = []

        # 自定义检测器结果
        if 'custom' in results and results['custom']:
            sections.append(self._generate_custom_findings(results['custom']))

        # Slither结果
        if 'slither' in results and results['slither']:
            sections.append(self._generate_slither_findings(results['slither']))

        if not sections:
            return '<div class="section"><h2>✅ 未发现问题</h2><p>恭喜！未发现明显的安全问题。</p></div>'

        return ''.join(sections)

    def _generate_custom_findings(self, findings: Dict) -> str:
        """生成自定义检测结果"""
        html = '<div class="section"><h2>🔍 自定义安全检查</h2>'

        for detector_name, issues in findings.items():
            for issue in issues:
                severity = issue.get('severity', 'Medium').lower()
                html += f'''
                <div class="finding {severity}">
                    <div class="finding-header">
                        <div class="finding-title">{issue.get('title', '安全')}</div>
                        <span class="severity-badge badge-{severity}">{severity.upper()}</span>
                    </div>
                    <div class="finding-meta">
                        📁 {issue.get('file', 'N/A')} | 行号: {issue.get('line', 'N/A')}
                    </div>
                    <p><strong>描述:</strong> {issue.get('description', 'N/A')}</p>
'''

                if 'code_snippet' in issue:
                    html += f'''
                    <div class="code-block">{issue['code_snippet']}</div>
'''

                if 'recommendation' in issue:
                    html += f'''
                    <div class="recommendation">
                        <strong>💡 建议:</strong> {issue['recommendation']}
                    </div>
'''

                html += '</div>'

        html += '</div>'
        return html

    def _generate_slither_findings(self, findings: Dict) -> str:
        """生成Slither检测结果"""
        html = '<div class="section"><h2>🔬 Slither 静态分析</h2>'

        for detector_name, issues in findings.items():
            html += f'<h3>{detector_name}</h3>'

            for issue in issues:
                severity = issue.get('severity', 'Medium').lower()
                html += f'''
                <div class="finding {severity}">
                    <div class="finding-header">
                        <div class="finding-title">检测到问题</div>
                        <span class="severity-badge badge-{severity}">{severity.upper()}</span>
                    </div>
                    <p>{issue.get('description', 'N/A')}</p>
                </div>'''

        html += '</div>'
        return html

    def _generate_remediation_section(self, results: Dict) -> str:
        """生成修复建议部分"""
        if 'remediation' not in results or not results['remediation']:
            return ''

        html = '<div class="section"><h2>🔧 修复建议</h2>'

        for issue_type, advice in results['remediation'].items():
            html += f'''
            <div class="remediation-item">
                <h3>📌 {advice.get('title', issue_type)}</h3>
                <p><strong>严重程度:</strong> <span class="severity-{advice.get('severity', 'Medium').lower()}">{advice.get('severity', 'Medium')}</span></p>
                <p><strong>描述:</strong> {advice.get('description', '')}</p>

                <h4>解决方案:</h4>
                <ul class="solution-list">
'''

            for solution in advice.get('solutions', []):
                html += f'                    <li>{solution}</li>\n'

            if 'code_example' in advice:
                html += f'''
                </ul>
                <h4>代码示例:</h4>
                <div class="code-block">{advice['code_example'].strip()}</div>
'''

            html += '            </div>\n'

        html += '</div>'
        return html
