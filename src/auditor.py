#!/usr/bin/env python3
"""
智能合约审计工具 - 主入口
集成Slither进行静态分析，提供常见安全检查
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from detectors.reentrancy import ReentrancyDetector
from detectors.integer_overflow import IntegerOverflowDetector
from detectors.access_control import AccessControlDetector
from reporters.html_reporter import HTMLReporter
from reporters.json_reporter import JSONReporter
from reporters.markdown_reporter import MarkdownReporter


class SmartContractAuditor:
    """智能合约审计器主类"""

    def __init__(self, target_path: str, output_dir: str = "reports"):
        self.target_path = Path(target_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 初始化检测器
        self.detectors = [
            ReentrancyDetector(),
            IntegerOverflowDetector(),
            AccessControlDetector()
        ]

        # 初始化报告生成器
        self.reporters = {
            "html": HTMLReporter(),
            "json": JSONReporter(),
            "md": MarkdownReporter()
        }

    def run_slither_analysis(self) -> Dict:
        """运行Slither静态分析"""
        print(f"🔍 Running Slither analysis on {self.target_path}...")

        try:
            from slither.slither import Slither

            slither = Slither(str(self.target_path))
            results = {}

            # 收集Slither检测结果
            for detector in slither.detectors:
                detector_name = detector.__class__.__name__
                findings = []
                for result in detector.detect():
                    findings.append({
                        "description": str(result),
                        "severity": "High" if "high" in str(result).lower() else "Medium",
                        "type": "slither"
                    })

                if findings:
                    results[detector_name] = findings

            print(f"✅ Slither analysis completed. Found {len(results)} detector types.")
            return results

        except ImportError:
            print("⚠️  Slither not installed. Skipping Slither analysis.")
            print("   Install with: pip install slither-analyzer")
            return {}
        except Exception as e:
            print(f"❌ Error running Slither: {e}")
            return {}

    def run_custom_detectors(self) -> Dict:
        """运行自定义检测器"""
        print(f"🔍 Running custom security checks...")

        all_findings = {}

        for detector in self.detectors:
            print(f"   Running {detector.name}...")
            try:
                findings = detector.detect(self.target_path)
                if findings:
                    all_findings[detector.name] = findings
            except Exception as e:
                print(f"   ⚠️  Error in {detector.name}: {e}")

        print(f"✅ Custom checks completed.")
        return all_findings

    def analyze(self) -> Dict:
        """执行完整审计流程"""
        print("\n" + "="*60)
        print("🛡️  Smart Contract Auditor Starting")
        print("="*60)

        # 运行Slither分析
        slither_results = self.run_slither_analysis()

        # 运行自定义检测器
        custom_results = self.run_custom_detectors()

        # 合并结果
        all_results = {
            "slither": slither_results,
            "custom": custom_results
        }

        # 添加修复建议
        all_results["remediation"] = self._generate_remediation(all_results)

        return all_results

    def _generate_remediation(self, results: Dict) -> Dict:
        """生成修复建议"""
        remediation = {}

        # 检查结果类型并提供修复建议
        if "custom" in results:
            for detector_name, findings in results["custom"].items():
                for finding in findings:
                    issue_type = finding.get("type", "")
                    if issue_type and issue_type not in remediation:
                        remediation[issue_type] = self._get_remediation_advice(issue_type)

        return remediation

    def _get_remediation_advice(self, issue_type: str) -> Dict:
        """获取特定问题的修复建议"""
        advice_map = {
            "reentrancy": {
                "severity": "Critical",
                "title": "重入攻击 (Reentrancy)",
                "description": "攻击者可以在状态更新前递归调用函数，可能导致资金被多次提取",
                "examples": [
                    "函数外部调用前未更新状态",
                    "使用.transfer()代替.call()但仍有重入风险"
                ],
                "solutions": [
                    "使用Checks-Effects-Interactions模式：先检查条件，再更新状态，最后执行外部调用",
                    "使用OpenZeppelin的ReentrancyGuard修饰器",
                    "对于简单支付，使用.transfer()或.send()（但有gas限制）",
                    "使用nonReentrant修饰器保护关键函数"
                ],
                "code_example": """
// ✅ 正确实现
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");

    // 1. 先更新状态
    balances[msg.sender] -= amount;

    // 2. 再执行外部调用
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}

// ❌ 错误实现
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");

    // ❌ 先执行外部调用
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");

    // ❌ 后更新状态
    balances[msg.sender] -= amount;
}
                """
            },
            "integer_overflow": {
                "severity": "High",
                "title": "整数溢出/下溢 (Integer Overflow/Underflow)",
                "description": "Solidity 0.8.x版本之前需要手动检查溢出，可能导致数值计算错误",
                "examples": [
                    "加法可能导致数值超出类型上限",
                    "减法可能导致数值变成巨大的正数"
                ],
                "solutions": [
                    "使用Solidity 0.8.x或更高版本（内置溢出检查）",
                    "使用OpenZeppelin的SafeMath库",
                    "使用unchecked块进行已验证的安全计算以节省gas",
                    "考虑使用uint256处理大数值"
                ],
                "code_example": """
// ✅ Solidity 0.8+ (自动溢出检查)
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;  // 自动检测溢出
}

// ✅ 使用SafeMath (Solidity 0.8之前)
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

function add(uint256 a, uint256 b) public pure returns (uint256) {
    return SafeMath.add(a, b);
}

// ✅ 使用unchecked (仅在确定安全时)
function subtract(uint256 a, uint256 b) public pure returns (uint256) {
    unchecked {
        return a - b;  // 仅在已知a >= b时使用
    }
}
                """
            },
            "access_control": {
                "severity": "High",
                "title": "访问控制绕过 (Access Control)",
                "description": "权限检查缺失或不当可能导致未授权用户执行特权操作",
                "examples": [
                    "缺失onlyOwner修饰器",
                    "使用tx.origin代替msg.sender进行身份验证",
                    "公开函数暴露敏感操作"
                ],
                "solutions": [
                    "使用OpenZeppelin的AccessControl或Ownable合约",
                    "使用基于角色的访问控制 (RBAC)",
                    "避免使用tx.origin进行授权检查",
                    "严格区分公开和内部函数",
                    "对修改状态的函数添加权限检查"
                ],
                "code_example": """
// ✅ 正确实现
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyContract is Ownable {
    function sensitiveFunction() external onlyOwner {
        // 只有所有者可以执行
    }
}

// ❌ 错误实现
contract VulnerableContract {
    function sensitiveFunction() external {
        // ❌ 无权限检查，任何人都可以执行
    }
}

// ❌ 危险：使用tx.origin
function withdraw() external {
    require(tx.origin == owner, "Not authorized");  // ❌ 容易被钓鱼攻击
    payable(msg.sender).transfer(address(this).balance);
}
                """
            }
        }

        return advice_map.get(issue_type, {
            "severity": "Medium",
            "title": issue_type,
            "description": "请进一步分析此问题",
            "solutions": ["请查阅相关安全文档和最佳实践"]
        })

    def generate_reports(self, results: Dict, formats: List[str] = None):
        """生成审计报告"""
        if formats is None:
            formats = ["html", "json", "md"]

        print(f"\n📄 Generating reports...")

        for format_type in formats:
            if format_type in self.reporters:
                reporter = self.reporters[format_type]
                report_path = self.output_dir / f"audit_report.{format_type}"
                reporter.generate(results, report_path)
                print(f"   ✅ {format_type.upper()} report: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description="智能合约审计工具 - Smart Contract Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 分析单个合约
  python auditor.py ./contracts/MyContract.sol

  # 分析Foundry项目
  python auditor.py ./foundry-project/

  # 指定输出格式和目录
  python auditor.py ./contracts/ -o ./reports -f html json
        """
    )

    parser.add_argument(
        "target",
        help="目标合约文件或项目目录"
    )

    parser.add_argument(
        "-o", "--output",
        default="reports",
        help="报告输出目录 (默认: reports)"
    )

    parser.add_argument(
        "-f", "--format",
        nargs="+",
        choices=["html", "json", "md"],
        default=["html", "json", "md"],
        help="报告格式 (默认: html json md)"
    )

    parser.add_argument(
        "--skip-slither",
        action="store_true",
        help="跳过Slither分析"
    )

    args = parser.parse_args()

    # 创建审计器
    auditor = SmartContractAuditor(args.target, args.output)

    # 执行分析
    results = auditor.analyze()

    # 生成报告
    auditor.generate_reports(results, args.format)

    print("\n" + "="*60)
    print("✅ Audit completed successfully!")
    print("="*60)


if __name__ == "__main__":
    main()
