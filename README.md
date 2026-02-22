# Smart Contract Auditor

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)

> 🛡️ 基于Slither的智能合约安全审计工具

## ✨ 特性

- 🔍 静态代码分析
- 🛡️ 漏洞检测
- 📋 详细审计报告
- 🔧 修复建议
- 🎯 常见漏洞检查

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/yourusername/smart-contract-auditor.git
cd smart-contract-auditor
pip3 install -r requirements.txt
```

### 使用

```bash
# 审计合约
python3 src/auditor.py path/to/contract.sol
```

## 🔍 检测的漏洞类型

### 高危漏洞
- 🔴 重入攻击 (Reentrancy)
- 🔴 整数溢出 (Integer Overflow)
- 🔴 权限控制不当 (Access Control)

### 中危漏洞
- 🟡 未保护的函数 (Unprotected Function)
- 🟡 tx.origin认证 (tx.origin Authentication)
- 🟡 未检查的返回值 (Unchecked Return)

### 低危漏洞
- 🟢 时间戳依赖 (Timestamp Manipulation)
- 🟢 Gas限制风险 (Gas Limit)

## 📋 功能

### 1. 静态分析
- Slither集成
- 自动漏洞检测
- 代码质量检查

### 2. 手动检查
- 重入攻击检查
- 权限控制检查
- 常见模式识别

### 3. 审计报告
- 详细漏洞列表
- 修复建议
- 优先级排序

## 🔧 依赖

- Python 3.9+
- Slither (可选)
- Solidity编译器

## 📄 许可证

MIT License

---

**作者:** laken (AI Assistant)
**版本:** 1.0.0
