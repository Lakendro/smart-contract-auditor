"""
检测器测试
"""

import pytest
from pathlib import Path
import sys

# 添加src目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detectors.reentrancy import ReentrancyDetector, IntegerOverflowDetector, AccessControlDetector


class TestReentrancyDetector:
    """测试重入攻击检测器"""

    def test_detect_vulnerable_contract(self):
        """测试检测易受攻击的合约"""
        detector = ReentrancyDetector()
        vulnerable_file = Path(__file__).parent.parent / "examples" / "VulnerableContract.sol"

        findings = detector.detect(vulnerable_file)

        # 应该发现至少一个重入问题
        reentrancy_findings = [f for f in findings if f['type'] == 'reentrancy']
        assert len(reentrancy_findings) > 0, "应该检测到重入漏洞"

    def test_detect_secure_contract(self):
        """测试安全合约"""
        detector = ReentrancyDetector()
        secure_file = Path(__file__).parent.parent / "examples" / "SecureContract.sol"

        findings = detector.detect(secure_file)

        # 安全合约应该使用ReentrancyGuard
        # 由于使用nonReentrant，可能不会报告问题
        print(f"安全合约发现 {len(findings)} 个问题")


class TestIntegerOverflowDetector:
    """测试整数溢出检测器"""

    def test_detect_vulnerable_contract(self):
        """测试检测易受攻击的合约"""
        detector = IntegerOverflowDetector()
        vulnerable_file = Path(__file__).parent.parent / "examples" / "VulnerableContract.sol"

        findings = detector.detect(vulnerable_file)

        # 应该发现整数溢出问题
        overflow_findings = [f for f in findings if f['type'] == 'integer_overflow']
        assert len(overflow_findings) > 0, "应该检测到整数溢出问题"

    def test_detect_secure_contract(self):
        """测试安全合约"""
        detector = IntegerOverflowDetector()
        secure_file = Path(__file__).parent.parent / "examples" / "SecureContract.sol"

        findings = detector.detect(secure_file)

        # Solidity 0.8.19 应该不会报告高严重性的溢出问题
        high_severity = [f for f in findings if f.get('severity') == 'High']
        # 可能有低严重性的SafeMath建议
        print(f"安全合约发现 {len(findings)} 个问题")


class TestAccessControlDetector:
    """测试访问控制检测器"""

    def test_detect_vulnerable_contract(self):
        """测试检测易受攻击的合约"""
        detector = AccessControlDetector()
        vulnerable_file = Path(__file__).parent.parent / "examples" / "VulnerableContract.sol"

        findings = detector.detect(vulnerable_file)

        # 应该发现访问控制问题
        access_findings = [f for f in findings if f['type'] == 'access_control']
        assert len(access_findings) > 0, "应该检测到访问控制问题"

    def test_detect_secure_contract(self):
        """测试安全合约"""
        detector = AccessControlDetector()
        secure_file = Path(__file__).parent.parent / "examples" / "SecureContract.sol"

        findings = detector.detect(secure_file)

        # 安全合约使用Ownable，应该问题较少
        print(f"安全合约发现 {len(findings)} 个访问控制问题")


class TestIntegration:
    """集成测试"""

    def test_full_audit_workflow(self):
        """测试完整审计流程"""
        from auditor import SmartContractAuditor

        vulnerable_file = Path(__file__).parent.parent / "examples" / "VulnerableContract.sol"
        output_dir = Path(__file__).parent.parent / "reports" / "test"

        auditor = SmartContractAuditor(str(vulnerable_file), str(output_dir))

        # 运行分析（跳过Slither以避免依赖问题）
        results = auditor.analyze()

        # 检查结果
        assert 'custom' in results
        assert 'slither' in results

        # 生成报告
        auditor.generate_reports(results, formats=['json'])

        # 检查报告文件
        report_file = output_dir / "audit_report.json"
        assert report_file.exists(), "报告文件应该存在"

        # 清理
        if report_file.exists():
            report_file.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
