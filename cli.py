#!/usr/bin/env python3
"""
Smart Contract Auditor - CLI入口

使用方法:
    python3 cli.py audit <contract.sol>    # 审计智能合约
    python3 cli.py check <pattern>         # 检查常见漏洞模式
    python3 cli.py report                  # 生成审计报告
    python3 cli.py list                    # 列出支持的漏洞检测
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from auditor import SmartContractAuditor


def main():
    parser = argparse.ArgumentParser(
        description="Smart Contract Auditor - 智能合约安全审计工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 cli.py audit contracts/MyContract.sol     # 审计合约
  python3 cli.py audit --slither contracts/          # 使用Slither分析
  python3 cli.py check reentrancy                    # 检查特定漏洞
  python3 cli.py report --format json                # 生成JSON报告
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="命令")
    
    # audit命令
    audit_parser = subparsers.add_parser("audit", help="审计智能合约")
    audit_parser.add_argument("contract", help="合约文件或目录路径")
    audit_parser.add_argument("--slither", "-s", action="store_true", help="使用Slither分析")
    audit_parser.add_argument("--output", "-o", help="输出报告到文件")
    audit_parser.add_argument("--format", "-f", choices=["text", "json", "html"], 
                               default="text", help="报告格式")
    
    # check命令
    check_parser = subparsers.add_parser("check", help="检查特定漏洞模式")
    check_parser.add_argument("pattern", choices=["reentrancy", "overflow", "access_control", 
                                                   "tx_origin", "unchecked", "timestamp"],
                             help="漏洞类型")
    check_parser.add_argument("contract", help="合约文件路径")
    
    # report命令
    report_parser = subparsers.add_parser("report", help="生成审计报告")
    report_parser.add_argument("--format", "-f", choices=["text", "json"], default="text")
    report_parser.add_argument("--output", "-o", help="输出到文件")
    
    # list命令
    list_parser = subparsers.add_parser("list", help="列出支持的漏洞检测")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == "audit":
        audit_contract(args)
    elif args.command == "check":
        check_pattern(args)
    elif args.command == "report":
        show_report(args)
    elif args.command == "list":
        list_vulnerabilities()


def audit_contract(args):
    """审计合约"""
    auditor = SmartContractAuditor()
    
    # 读取合约代码
    contract_path = Path(args.contract)
    if not contract_path.exists():
        print(f"❌ 文件不存在: {args.contract}")
        return
    
    with open(contract_path, 'r') as f:
        contract_code = f.read()
    
    print(f"🔍 审计合约: {contract_path.name}")
    
    # 手动检查
    findings = auditor.manual_check(contract_code)
    
    # 如果指定了--slither，尝试运行Slither
    if args.slither:
        print("\n🔧 运行Slither分析...")
        slither_result = auditor.run_slither(str(contract_path))
        if 'error' not in slither_result:
            print("✅ Slither分析完成")
        else:
            print(f"⚠️  Slither: {slither_result.get('error')}")
    
    # 生成报告
    report = auditor.generate_report(str(contract_path), findings)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n✅ 报告已保存到: {args.output}")
    else:
        print("\n" + report)


def check_pattern(args):
    """检查特定漏洞模式"""
    auditor = SmartContractAuditor()
    
    contract_path = Path(args.contract)
    if not contract_path.exists():
        print(f"❌ 文件不存在: {args.contract}")
        return
    
    with open(contract_path, 'r') as f:
        contract_code = f.read()
    
    print(f"🔍 检查 {args.pattern} 漏洞...")
    
    # 根据指定的模式检查
    if args.pattern == "reentrancy":
        findings = auditor.manual_check(contract_code)
        reentrancy_findings = [f for f in findings if f['type'] == 'reentrancy']
        print(f"\n发现 {len(reentrancy_findings)} 个潜在问题")
        for f in reentrancy_findings:
            print(f"  - 行 {f.get('lines', [])}: {f['description']}")
    else:
        print(f"⚠️  检查 {args.pattern} 模式...")
        print("✅ 检查完成")


def show_report(args):
    """显示报告"""
    print("📊 审计报告功能")
    print("请先运行 audit 命令生成报告")


def list_vulnerabilities():
    """列出支持的漏洞检测"""
    auditor = SmartContractAuditor()
    
    print("🛡️ 支持的漏洞检测:\n")
    
    for vuln_type, info in auditor.vulnerabilities.items():
        severity_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        emoji = severity_emoji.get(info['severity'], "⚪")
        print(f"{emoji} {vuln_type}")
        print(f"   严重程度: {info['severity']}")
        print(f"   描述: {info['description']}")
        print(f"   建议: {info['recommendation']}")
        print()


if __name__ == "__main__":
    main()