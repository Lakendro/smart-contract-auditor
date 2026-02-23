#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart Contract Auditor - 主程序
基于Slither的智能合约安全审计工具
"""

import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List


class SmartContractAuditor:
    """智能合约审计器"""

    def __init__(self):
        self.vulnerabilities = {
            'reentrancy': {
                'severity': 'HIGH',
                'description': '重入攻击漏洞',
                'recommendation': '使用ReentrancyGuard或检查-效果-交互模式'
            },
            'integer_overflow': {
                'severity': 'HIGH',
                'description': '整数溢出漏洞',
                'recommendation': '使用Solidity 0.8+或SafeMath库'
            },
            'access_control': {
                'severity': 'HIGH',
                'description': '权限控制不当',
                'recommendation': '实现适当的访问控制修饰符'
            },
            'unprotected_function': {
                'severity': 'MEDIUM',
                'description': '未保护的函数',
                'recommendation': '添加onlyOwner或其他访问控制'
            },
            'tx_origin': {
                'severity': 'MEDIUM',
                'description': '使用tx.origin进行认证',
                'recommendation': '使用msg.sender替代tx.origin'
            },
            'unchecked_return': {
                'severity': 'MEDIUM',
                'description': '未检查的返回值',
                'recommendation': '检查所有外部调用的返回值'
            },
            'timestamp_manipulation': {
                'severity': 'LOW',
                'description': '时间戳依赖',
                'recommendation': '不要依赖block.timestamp进行关键逻辑'
            },
            'gas_limit': {
                'severity': 'LOW',
                'description': 'Gas限制风险',
                'recommendation': '优化循环和批量操作'
            }
        }

    def run_slither(self, contract_path: str) -> Dict:
        """
        运行Slither进行静态分析

        Args:
            contract_path: 合约文件路径

        Returns:
            分析结果
        """
        try:
            result = subprocess.run(
                ['slither', contract_path, '--json', '-'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {
                    'error': result.stderr,
                    'timestamp': datetime.now().isoformat()
                }
        except subprocess.TimeoutExpired:
            return {
                'error': 'Slither execution timeout',
                'timestamp': datetime.now().isoformat()
            }
        except FileNotFoundError:
            return {
                'error': 'Slither not installed',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def manual_check(self, contract_code: str) -> List[Dict]:
        """
        手动检查常见漏洞

        Args:
            contract_code: 合约代码

        Returns:
            发现的漏洞列表
        """
        findings = []

        # 检查重入攻击
        if 'call.value' in contract_code or '.call{value:' in contract_code:
            if 'nonReentrant' not in contract_code and 'ReentrancyGuard' not in contract_code:
                findings.append({
                    'type': 'reentrancy',
                    'severity': self.vulnerabilities['reentrancy']['severity'],
                    'description': self.vulnerabilities['reentrancy']['description'],
                    'recommendation': self.vulnerabilities['reentrancy']['recommendation'],
                    'lines': self._find_lines(contract_code, ['call.value', '.call{value:'])
                })

        # 检查tx.origin
        if 'tx.origin' in contract_code:
            findings.append({
                'type': 'tx_origin',
                'severity': self.vulnerabilities['tx_origin']['severity'],
                'description': self.vulnerabilities['tx_origin']['description'],
                'recommendation': self.vulnerabilities['tx_origin']['recommendation'],
                'lines': self._find_lines(contract_code, ['tx.origin'])
            })

        # 检查未保护的函数
        if 'public' in contract_code or 'external' in contract_code:
            if 'onlyOwner' not in contract_code and 'AccessControl' not in contract_code:
                findings.append({
                    'type': 'unprotected_function',
                    'severity': self.vulnerabilities['unprotected_function']['severity'],
                    'description': self.vulnerabilities['unprotected_function']['description'],
                    'recommendation': self.vulnerabilities['unprotected_function']['recommendation'],
                    'lines': self._find_lines(contract_code, ['public', 'external'])
                })

        # 检查时间戳依赖
        if 'block.timestamp' in contract_code or 'now' in contract_code:
            findings.append({
                'type': 'timestamp_manipulation',
                'severity': self.vulnerabilities['timestamp_manipulation']['severity'],
                'description': self.vulnerabilities['timestamp_manipulation']['description'],
                'recommendation': self.vulnerabilities['timestamp_manipulation']['recommendation'],
                'lines': self._find_lines(contract_code, ['block.timestamp', 'now'])
            })

        return findings

    def _find_lines(self, code: str, keywords: List[str]) -> List[int]:
        """查找包含关键词的行号"""
        lines = []
        for i, line in enumerate(code.split('\n'), 1):
            if any(keyword in line for keyword in keywords):
                lines.append(i)
        return lines

    def generate_report(self, contract_path: str, findings: List[Dict]) -> str:
        """
        生成审计报告

        Args:
            contract_path: 合约路径
            findings: 发现的漏洞列表

        Returns:
            报告文本
        """
        lines = [
            "# 智能合约安全审计报告",
            "=" * 60,
            f"合约路径: {contract_path}",
            f"审计时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"发现漏洞: {len(findings)}个",
            "",
            "## 漏洞详情",
            "-" * 60,
        ]

        if not findings:
            lines.append("\n✅ 未发现明显漏洞")
        else:
            # 按严重程度分组
            severity_order = {'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            sorted_findings = sorted(findings, key=lambda x: severity_order.get(x['severity'], 99))

            for i, finding in enumerate(sorted_findings, 1):
                severity_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
                lines.extend([
                    f"\n### {i}. {finding['description']} {severity_emoji.get(finding['severity'], '⚪')}",
                    f"- **类型:** {finding['type']}",
                    f"- **严重程度:** {finding['severity']}",
                    f"- **建议:** {finding['recommendation']}",
                ])
                if finding.get('lines'):
                    lines.append(f"- **位置:** 行 {', '.join(map(str, finding['lines']))}")

        lines.extend([
            "",
            "## 审计建议",
            "-" * 60,
            "",
            "### 高优先级",
            "1. 修复所有HIGH级别漏洞",
            "2. 添加全面的访问控制",
            "3. 实现重入攻击保护",
            "",
            "### 中优先级",
            "1. 修复MEDIUM级别漏洞",
            "2. 优化Gas使用",
            "3. 添加事件日志",
            "",
            "### 低优先级",
            "1. 修复LOW级别漏洞",
            "2. 改进代码注释",
            "3. 优化代码结构",
            "",
            "## 免责声明",
            "-" * 60,
            "",
            "本审计报告仅供参考，不构成任何形式的担保。",
            "建议在进行生产部署前，请专业审计团队进行全面审计。",
            "",
            "=" * 60,
            "报告结束",
        ])

        return "\n".join(lines)

    def save_report(self, report: str, output_path: str):
        """保存报告到文件"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"✅ 报告已保存到 {output_path}")


def main():
    """主函数"""
    import sys

    if len(sys.argv) < 2:
        print("用法: python3 auditor.py <contract_path>")
        sys.exit(1)

    contract_path = sys.argv[1]
    auditor = SmartContractAuditor()

    print(f"🔍 正在审计合约: {contract_path}")

    # 读取合约代码
    with open(contract_path, 'r', encoding='utf-8') as f:
        contract_code = f.read()

    # 手动检查
    print("📋 执行手动检查...")
    findings = auditor.manual_check(contract_code)

    # 尝试运行Slither
    print("🔧 尝试运行Slither...")
    slither_result = auditor.run_slither(contract_path)
    if 'error' not in slither_result:
        print("✅ Slither分析完成")
        # 合并Slither结果
        # 这里可以添加更多的结果处理逻辑
    else:
        print(f"⚠️  Slither分析失败: {slither_result.get('error')}")

    # 生成报告
    print("📝 生成审计报告...")
    report = auditor.generate_report(contract_path, findings)
    print("\n" + report)

    # 保存报告
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = f'audit_report_{timestamp}.md'
    auditor.save_report(report, output_path)


if __name__ == '__main__':
    main()
