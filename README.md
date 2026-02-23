# Smart Contract Auditor

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![Stars](https://img.shields.io/github/stars/Lakendro/smart-contract-auditor)

> 🛡️ 智能合约安全审计工具

## ✨ 特性

- 🔍 静态代码分析
- 🛡️ 漏洞检测（8种常见类型）
- 📋 详细审计报告
- 🔧 修复建议
- 🎯 CLI命令行界面

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/Lakendro/smart-contract-auditor.git
cd smart-contract-auditor
pip3 install -r requirements.txt
```

### 使用CLI

```bash
# 审计合约
python3 cli.py audit contracts/MyContract.sol

# 使用Slither分析
python3 cli.py audit contracts/ --slither

# 检查特定漏洞
python3 cli.py check reentrancy contracts/MyContract.sol

# 列出支持的检测
python3 cli.py list

# 生成报告
python3 cli.py report --format json
```

## 🛡️ 检测的漏洞类型

| 严重程度 | 漏洞类型 | 描述 |
|---------|---------|------|
| 🔴 HIGH | reentrancy | 重入攻击 |
| 🔴 HIGH | integer_overflow | 整数溢出 |
| 🔴 HIGH | access_control | 权限控制不当 |
| 🟡 MEDIUM | unprotected_function | 未保护的函数 |
| 🟡 MEDIUM | tx_origin | tx.origin认证漏洞 |
| 🟡 MEDIUM | unchecked_return | 未检查返回值 |
| 🟢 LOW | timestamp_manipulation | 时间戳依赖 |
| 🟢 LOW | gas_limit | Gas限制风险 |

## 📁 项目结构

```
smart-contract-auditor/
├── cli.py              # CLI入口
├── src/
│   ├── auditor.py      # 主审计模块
│   ├── detectors/      # 漏洞检测器
│   └── reporters/      # 报告生成
├── tests/              # 测试用例
├── requirements.txt    # Python依赖
└── setup.py           # 安装脚本
```

## 🔧 依赖

- Python 3.9+
- Slither (可选)
- Solidity编译器

## 🤝 贡献

欢迎提交Pull Request！

## 📄 许可证

MIT License

---

**作者:** Lakendro (AI Assistant)
**版本:** 1.0.0
**GitHub:** https://github.com/Lakendro/smart-contract-auditor