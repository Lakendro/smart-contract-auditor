"""
重入攻击检测器
检测可能的重入漏洞
"""

import re
from pathlib import Path
from typing import Dict, List
from abc import ABC, abstractmethod


class BaseDetector(ABC):
    """检测器基类"""

    def __init__(self):
        self.name = self.__class__.__name__
        self.findings = []

    @abstractmethod
    def detect(self, target_path: Path) -> List[Dict]:
        """执行检测"""
        pass


class ReentrancyDetector(BaseDetector):
    """重入攻击检测器"""

    def __init__(self):
        super().__init__()
        self.name = "Reentrancy Detector"

    def detect(self, target_path: Path) -> List[Dict]:
        """检测重入漏洞"""
        findings = []
        solidity_files = []

        # 查找所有Solidity文件
        if target_path.is_file() and target_path.suffix == ".sol":
            solidity_files.append(target_path)
        else:
            solidity_files.extend(target_path.rglob("*.sol"))

        for sol_file in solidity_files:
            content = sol_file.read_text()
            findings.extend(self._analyze_file(sol_file, content))

        return findings

    def _analyze_file(self, file_path: Path, content: str) -> List[Dict]:
        """分析单个文件"""
        findings = []
        lines = content.split('\n')

        # 模式1: 外部调用后更新状态
        call_pattern = re.compile(
            r'\.(call|delegatecall|staticcall|transfer|send)\s*\{.*value:.*\}\s*\(',
            re.MULTILINE | re.DOTALL
        )

        for i, line in enumerate(lines, 1):
            # 检查外部调用
            if call_pattern.search(line):
                # 检查是否使用ReentrancyGuard
                has_guard = self._check_reentrancy_guard(lines[:i])

                if not has_guard:
                    findings.append({
                        "file": str(file_path),
                        "line": i,
                        "type": "reentrancy",
                        "severity": "High",
                        "title": "潜在重入漏洞",
                        "description": "检测到外部调用，未明确使用重入保护",
                        "code_snippet": line.strip(),
                        "recommendation": "使用Checks-Effects-Interactions模式或ReentrancyGuard修饰器"
                    })

        # 模式2: 使用tx.origin进行授权
        tx_origin_pattern = re.compile(r'tx\.origin\s*==\s*\w+')

        for i, line in enumerate(lines, 1):
            if tx_origin_pattern.search(line):
                findings.append({
                    "file": str(file_path),
                    "line": i,
                    "type": "access_control",  # 也归类为访问控制问题
                    "severity": "High",
                    "title": "使用tx.origin进行授权",
                    "description": "使用tx.origin进行身份验证容易受到钓鱼攻击",
                    "code_snippet": line.strip(),
                    "recommendation": "使用msg.sender代替tx.origin"
                })

        return findings

    def _check_reentrancy_guard(self, lines_before_call: List[str]) -> bool:
        """检查是否使用了ReentrancyGuard"""
        content_before = '\n'.join(lines_before_call)

        # 检查是否有nonReentrant修饰器
        if re.search(r'nonReentrant', content_before):
            return True

        # 检查是否导入OpenZeppelin的ReentrancyGuard
        if re.search(r'import.*ReentrancyGuard', content_before):
            return True

        return False


class IntegerOverflowDetector(BaseDetector):
    """整数溢出检测器"""

    def __init__(self):
        super().__init__()
        self.name = "Integer Overflow Detector"

    def detect(self, target_path: Path) -> List[Dict]:
        """检测整数溢出漏洞"""
        findings = []
        solidity_files = []

        # 查找所有Solidity文件
        if target_path.is_file() and target_path.suffix == ".sol":
            solidity_files.append(target_path)
        else:
            solidity_files.extend(target_path.rglob("*.sol"))

        for sol_file in solidity_files:
            content = sol_file.read_text()
            findings.extend(self._analyze_file(sol_file, content))

        return findings

    def _analyze_file(self, file_path: Path, content: str) -> List[Dict]:
        """分析单个文件"""
        findings = []
        lines = content.split('\n')

        # 检查Solidity版本
        version_pattern = re.compile(r'pragma\s+solidity\s+\^?([\d.]+)')

        solidity_version = None
        for i, line in enumerate(lines, 1):
            match = version_pattern.search(line)
            if match:
                solidity_version = match.group(1)
                break

        # Solidity 0.8.0+ 有内置溢出检查
        if solidity_version:
            major = int(solidity_version.split('.')[0])
            if major >= 8:
                # 检查是否还在使用SafeMath（可能是多余的）
                safemath_import = re.search(r'import.*SafeMath', content)
                if safemath_import:
                    findings.append({
                        "file": str(file_path),
                        "line": 1,
                        "type": "integer_overflow",
                        "severity": "Low",
                        "title": "可能不需要SafeMath",
                        "description": f"Solidity {solidity_version}+ 已内置溢出检查，SafeMath可能是多余的",
                        "recommendation": "考虑移除SafeMath以节省gas，或保留以保持代码清晰"
                    })
                return findings

        # 旧版本Solidity需要检查SafeMath使用
        # 检查算术操作
        arithmetic_patterns = [
            r'\+\s*=',  # +=
            r'-\s*=',   # -=
            r'\*\s*=',  # *=
            r'/\s*=',   # /=
            r'%\s*=',   # %=
            r'[a-zA-Z_]\w*\s*\+\s*[a-zA-Z_]\w*',  # 加法
            r'[a-zA-Z_]\w*\s*-\s*[a-zA-Z_]\w*',   # 减法
            r'[a-zA-Z_]\w*\s*\*\s*[a-zA-Z_]\w*',  # 乘法
        ]

        for i, line in enumerate(lines, 1):
            # 跳过注释和字符串
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue

            for pattern in arithmetic_patterns:
                if re.search(pattern, line):
                    # 检查是否使用SafeMath
                    if not re.search(r'SafeMath\.(add|sub|mul|div|mod)', line):
                        findings.append({
                            "file": str(file_path),
                            "line": i,
                            "type": "integer_overflow",
                            "severity": "High",
                            "title": "潜在的整数溢出/下溢",
                            "description": "检测到算术操作，未使用SafeMath保护",
                            "code_snippet": line.strip(),
                            "recommendation": "使用SafeMath库或升级到Solidity 0.8.0+"
                        })
                    break

        return findings


class AccessControlDetector(BaseDetector):
    """访问控制检测器"""

    def __init__(self):
        super().__init__()
        self.name = "Access Control Detector"

    def detect(self, target_path: Path) -> List[Dict]:
        """检测访问控制问题"""
        findings = []
        solidity_files = []

        # 查找所有Solidity文件
        if target_path.is_file() and target_path.suffix == ".sol":
            solidity_files.append(target_path)
        else:
            solidity_files.extend(target_path.rglob("*.sol"))

        for sol_file in solidity_files:
            content = sol_file.read_text()
            findings.extend(self._analyze_file(sol_file, content))

        return findings

    def _analyze_file(self, file_path: Path, content: str) -> List[Dict]:
        """分析单个文件"""
        findings = []
        lines = content.split('\n')

        # 模式1: 缺失权限修饰器的敏感函数
        sensitive_functions = [
            r'function\s+\w+.*\{',
            r'function\s+mint\s*\(',
            r'function\s+burn\s*\(',
            r'function\s+withdraw\s*\(',
            r'function\s+setOwner\s*\(',
            r'function\s+transferOwnership\s*\(',
        ]

        in_function = False
        function_start = 0
        current_function = ""

        for i, line in enumerate(lines, 1):
            # 检测函数定义
            for pattern in sensitive_functions:
                if re.search(pattern, line):
                    function_start = i
                    current_function = line.strip()
                    in_function = True

                    # 检查是否有权限修饰器
                    has_modifier = re.search(r'(onlyOwner|adminOnly|restricted)', line)

                    # 检查函数是否为public/external
                    is_public = re.search(r'\b(public|external)\b', line)

                    if is_public and not has_modifier:
                        # 检查函数名是否暗示需要权限
                        func_name_match = re.search(r'function\s+(\w+)', line)
                        if func_name_match:
                            func_name = func_name_match.group(1).lower()

                            # 敏感函数列表
                            sensitive_keywords = ['mint', 'burn', 'withdraw', 'set', 'add', 'remove',
                                                'owner', 'admin', 'transfer', 'emergency']

                            if any(keyword in func_name for keyword in sensitive_keywords):
                                findings.append({
                                    "file": str(file_path),
                                    "line": i,
                                    "type": "access_control",
                                    "severity": "High",
                                    "title": "缺失权限检查",
                                    "description": f"函数 {func_name} 看起来需要权限保护但没有修饰器",
                                    "code_snippet": line.strip(),
                                    "recommendation": "添加onlyOwner或适当的访问控制修饰器"
                                })
                    break

        # 模式2: 可构造函数参数未验证
        constructor_pattern = re.compile(r'constructor\s*\(([^)]*)\)')
        for i, line in enumerate(lines, 1):
            match = constructor_pattern.search(line)
            if match:
                params = match.group(1)
                # 检查是否有参数但没有验证
                if params and not 'require' in params and 'if' not in params:
                    # 检查后续几行是否有验证
                    next_lines = '\n'.join(lines[i:min(i+5, len(lines))])
                    if 'require' not in next_lines and 'if' not in next_lines:
                        findings.append({
                            "file": str(file_path),
                            "line": i,
                            "type": "access_control",
                            "severity": "Medium",
                            "title": "构造函数参数未验证",
                            "description": "构造函数参数可能需要验证",
                            "code_snippet": line.strip(),
                            "recommendation": "添加参数验证逻辑"
                        })

        return findings
