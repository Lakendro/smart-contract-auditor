# 🛡️ Smart Contract Auditor

一个强大的智能合约安全审计工具，集成Slither静态分析和自定义安全检查，自动生成详细的审计报告。

## ✨ 特性

- 🔍 **Slither集成** - 利用业界标准的Slither静态分析工具
- 🎯 **自定义检测器** - 针对常见安全问题的专用检测
- 📊 **多格式报告** - 支持HTML、JSON、Markdown格式输出
- 🔧 **修复建议** - 提供详细的代码修复方案和示例
- 🚀 **简单易用** - 命令行工具，快速上手
- 🌐 **Foundry支持** - 完美兼容Foundry开发环境

## 🎯 检测的安全问题

### 核心检测器

1. **重入攻击 (Reentrancy)**
   - 外部调用后的状态更新
   - 缺失ReentrancyGuard保护
   - tx.origin钓鱼攻击

2. **整数溢出/下溢 (Integer Overflow/Underflow)**
   - Solidity版本检查
   - SafeMath使用验证
   - 算术操作安全审查

3. **访问控制 (Access Control)**
   - 缺失权限修饰器
   - 敏感函数公开暴露
   - 构造函数参数验证

## 📦 安装

### 前置要求

- Python 3.8+
- pip

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/yourusername/smart-contract-auditor.git
cd smart-contract-auditor

# 安装依赖
pip install -r requirements.txt

# 可选：安装Slither（推荐）
pip install slither-analyzer

# 可选：安装Foundry（用于测试）
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## 🚀 使用方法

### 基本用法

```bash
# 分析单个合约文件
python src/auditor.py path/to/Contract.sol

# 分析整个项目目录
python src/auditor.py path/to/project/

# 指定输出目录
python src/auditor.py path/to/project/ -o ./reports

# 选择报告格式
python src/auditor.py path/to/project/ -f html json
```

### 完整参数

```bash
python src/auditor.py [目标路径] [选项]

选项:
  -o, --output     报告输出目录 (默认: reports)
  -f, --format     报告格式: html, json, md (默认: 全部)
  --skip-slither   跳过Slither分析
  -h, --help       显示帮助信息
```

### 使用示例

```bash
# 分析Foundry项目
python src/auditor.py ./foundry-project/src/

# 只生成JSON报告
python src/auditor.py ./contracts/ -f json

# 跳过Slither，只运行自定义检测器
python src/auditor.py ./contracts/ --skip-slither
```

## 📄 报告格式

### HTML报告

- 可视化界面，易于阅读
- 交互式设计，快速定位问题
- 包含代码高亮和修复建议
- 自动打开浏览器查看

### JSON报告

- 机器可读格式
- 适合CI/CD集成
- 易于后续处理和分析

### Markdown报告

- 适合文档管理
- 可直接用于GitHub
- 版本控制友好

## 🔬 检测器详解

### 重入攻击检测器

检测以下模式：
- `.call{value:}()` 外部调用
- 状态更新在外部调用之后
- 缺失`nonReentrant`修饰器

**示例漏洞代码：**
```solidity
// ❌ 易受攻击
function withdraw() public {
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");
    balance = 0;  // 错误：状态更新在外部调用后
}
```

### 整数溢出检测器

检测以下问题：
- Solidity版本检查
- 算术操作未保护
- SafeMath使用不当

**示例修复：**
```solidity
// ✅ 安全代码 (Solidity 0.8+)
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;  // 自动溢出检查
}
```

### 访问控制检测器

检测以下模式：
- 缺失`onlyOwner`修饰器
- 敏感函数公开访问
- 构造函数参数未验证

**示例修复：**
```solidity
// ✅ 安全代码
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyContract is Ownable {
    function sensitiveFunction() external onlyOwner {
        // 只有所有者可以执行
    }
}
```

## 🧪 测试

### 运行测试

```bash
# 运行所有测试
python -m pytest tests/

# 运行特定测试
python -m pytest tests/test_reentrancy.py -v

# 生成覆盖率报告
python -m pytest --cov=src tests/
```

### 测试合约

项目包含示例易受攻击的合约用于测试：

```bash
# 使用示例合约测试
python src/auditor.py examples/VulnerableContract.sol
```

## 🔧 开发

### 项目结构

```
smart-contract-auditor/
├── src/
│   ├── auditor.py           # 主入口
│   ├── detectors/           # 检测器模块
│   │   ├── __init__.py
│   │   └── reentrancy.py    # 检测器实现
│   └── reporters/           # 报告生成器
│       ├── __init__.py
│       ├── html_reporter.py
│       ├── json_reporter.py
│       └── markdown_reporter.py
├── tests/                   # 测试文件
├── examples/               # 示例合约
├── reports/                # 报告输出目录
├── requirements.txt        # Python依赖
└── README.md              # 本文档
```

### 添加新检测器

1. 创建新的检测器类继承`BaseDetector`
2. 实现`detect()`方法
3. 返回问题列表

```python
from detectors.base import BaseDetector

class MyDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "My Detector"

    def detect(self, target_path: Path) -> List[Dict]:
        # 实现检测逻辑
        findings = []
        # ...
        return findings
```

### 添加新报告格式

1. 创建新的报告器类
2. 实现`generate()`方法

```python
from reporters.base import BaseReporter

class MyReporter(BaseReporter):
    def generate(self, results: Dict, output_path: Path):
        # 生成报告
        pass
```

## 🤝 贡献

欢迎贡献！请遵循以下步骤：

1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 📝 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件

## 🙏 致谢

- [Slither](https://github.com/crytic/slither) - 静态分析工具
- [Foundry](https://getfoundry.sh/) - 以太坊开发工具链
- [OpenZeppelin](https://openzeppelin.com/) - 安全智能合约库

## ⚠️ 免责声明

本工具旨在辅助安全审计，但不能替代专业的人工代码审查。使用本工具发现的任何问题都应进行仔细验证。对于因使用本工具造成的任何损失，开发者不承担责任。

## 📧 联系方式

- 提交问题: [GitHub Issues](https://github.com/yourusername/smart-contract-auditor/issues)
- 邮箱: your.email@example.com

---

**⭐ 如果这个项目对你有帮助，请给个Star！**
