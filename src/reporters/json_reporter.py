"""
JSON报告生成器
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict


class JSONReporter:
    """JSON格式报告生成器"""

    def generate(self, results: Dict, output_path: Path):
        """生成JSON报告"""
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "Smart Contract Auditor",
                "version": "1.0.0"
            },
            "summary": self._generate_summary(results),
            "findings": self._organize_findings(results),
            "remediation": results.get("remediation", {})
        }

        output_path.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )

    def _generate_summary(self, results: Dict) -> Dict:
        """生成摘要信息"""
        summary = {
            "total_findings": 0,
            "slither_findings": 0,
            "custom_findings": 0,
            "severity_breakdown": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }

        for category in ['slither', 'custom']:
            if category in results:
                for detector_name, findings in results[category].items():
                    count = len(findings)
                    summary[f"{category}_findings"] += count
                    summary["total_findings"] += count

                    for finding in findings:
                        severity = finding.get('severity', 'Medium').lower()
                        if severity in summary['severity_breakdown']:
                            summary['severity_breakdown'][severity] += 1

        return summary

    def _organize_findings(self, results: Dict) -> Dict:
        """组织发现的问题"""
        organized = {}

        for category in ['slither', 'custom']:
            if category in results:
                organized[category] = results[category]

        return organized
