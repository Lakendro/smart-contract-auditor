"""
Markdown报告生成器
"""

from datetime import datetime
from pathlib import Path
from typing import Dict


class MarkdownReporter:
    """Markdown格式报告生成器"""

    def generate(self, results: Dict, output_path: Path):
        """生成Markdown报告"""
        markdown_content = self._generate_markdown(results)
        output_path.write_text(markdown_content, encoding='utf-8')

    def _generate_markdown(self, results: Dict) -> str:
        """生成Markdown内容"""
        total_findings = self._count_findings(results)
        severity_breakdown = self._get_severity_breakdown(results)

        md = f"""# 🛡️ 智能合约审计报告

**生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**审计工具:** Smart Contract Auditor v1.0.0

---

## 📊 审计摘要

| 指标 | 数量 |
|------|------|
| 总问题数 | {total_findings['total']} |
| 严重 (Critical) | 🔴 {severity_breakdown.get('critical', 0)} |
| 高危 (High) | 🟠 {severity_breakdown.get('high', 0)} |
| 中危 (Medium) | 🟡 {severity_breakdown.get('medium', 0)} |
| 低危 (Low) | 🟢 {severity_breakdown.get('low', 0)} |

---

## 🔍 自定义安全检查

{self._generate_custom_findings(results)}

---

## 🔬 Slither 静态分析

{self._generate_slither_findings(results)}

---

## 🔧 修复建议

{self._generate_remediation_section(results)}

---

## 📝 附录

### 严重程度定义

- **严重 (Critical):** 可能导致资金损失的漏洞，必须立即修复
- **高危 (High):** 严重的安全问题，应在部署前修复
- **中危 (Medium):** 潜在的安全问题，建议修复
- **低危 (Low):** 代码质量或优化建议

### 后续步骤

1. 仔细审查所有发现的问题
2. 根据优先级进行修复
3. 重新运行审计工具验证修复
4. 进行人工代码审查
5. 考虑专业第三方审计

---

*此报告由 Smart Contract Auditor 自动生成。建议配合人工审查使用。*
"""
        return md

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

    def _generate_custom_findings(self, results: Dict) -> str:
        """生成自定义检测结果"""
        if 'custom' not in results or not results['custom']:
            return "✅ 未发现自定义检测安全问题"

        md = ""

        for detector_name, issues in results['custom'].items():
            md += f"\n### {detector_name}\n\n"

            for issue in issues:
                severity = issue.get('severity', 'Medium').lower()
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(severity, '⚪')

                md += f"#### {severity_emoji} {issue.get('title', '安全')}\n\n"
                md += f"**严重程度:** {severity.upper()}\n\n"
                md += f"**文件:** `{issue.get('file', 'N/A')}` (行号: {issue.get('line', 'N/A')})\n\n"
                md += f"**描述:** {issue.get('description', 'N/A')}\n\n"

                if 'code_snippet' in issue:
                    md += "**代码片段:**\n\n```solidity\n"
                    md += issue['code_snippet']
                    md += "\n```\n\n"

                if 'recommendation' in issue:
                    md += f"**建议:** {issue['recommendation']}\n\n"

                md += "---\n\n"

        return md

    def _generate_slither_findings(self, results: Dict) -> str:
        """生成Slither检测结果"""
        if 'slither' not in results or not results['slither']:
            return "✅ Slither未发现问题"

        md = ""

        for detector_name, issues in results['slither'].items():
            md += f"\n### {detector_name}\n\n"

            for issue in issues:
                severity = issue.get('severity', 'Medium').lower()
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(severity, '⚪')

                md += f"- {severity_emoji} **{severity.upper()}**: {issue.get('description', 'N/A')}\n\n"

        return md

    def _generate_remediation_section(self, results: Dict) -> str:
        """生成修复建议部分"""
        if 'remediation' not in results or not results['remediation']:
            return "无特定修复建议"

        md = ""

        for issue_type, advice in results['remediation'].items():
            md += f"\n### {advice.get('title', issue_type)}\n\n"
            md += f"**严重程度:** {advice.get('severity', 'Medium')}\n\n"
            md += f"**描述:** {advice.get('description', '')}\n\n"

            md += "**解决方案:**\n\n"
            for solution in advice.get('solutions', []):
                md += f"- {solution}\n"

            if 'code_example' in advice:
                md += "\n**代码示例:**\n\n```solidity\n"
                md += advice['code_example'].strip()
                md += "\n```\n\n"

            md += "---\n\n"

        return md
