// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecureContract
 * @dev 这是一个安全的合约示例，展示了如何修复常见安全漏洞
 */
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureContract is Ownable, ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposit(address indexed from, uint256 amount);
    event Withdrawal(address indexed to, uint256 amount);

    constructor() Ownable(msg.sender) {
        // ✅ Ownable会自动验证msg.sender
    }

    // ✅ 安全的存款函数 - Solidity 0.8.19有内置溢出检查
    function deposit() external payable {
        balances[msg.sender] += msg.value;  // ✅ 自动溢出检查
        emit Deposit(msg.sender, msg.value);
    }

    // ✅ 安全的提取函数 - 使用ReentrancyGuard保护
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ✅ 先更新状态 (Checks-Effects-Interactions模式)
        balances[msg.sender] -= amount;

        // ✅ 后执行外部调用
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    // ✅ 使用onlyOwner修饰器
    function emergencyWithdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    // ✅ 使用onlyOwner修饰器保护mint函数
    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid address");  // ✅ 参数验证
        balances[to] += amount;  // ✅ Solidity 0.8+自动溢出检查
    }

    // ✅ 使用onlyOwner修饰器
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");  // ✅ 参数验证
        _transferOwnership(newOwner);
    }

    // ✅ 安全的函数 - 带参数验证和权限检查
    function transfer(address target, uint256 value) external onlyOwner {
        require(target != address(0), "Invalid address");
        require(value <= address(this).balance, "Insufficient balance");

        payable(target).transfer(value);
    }

    // ✅ 安全的乘法 - Solidity 0.8+自动溢出检查
    function calculateReward(uint256 base, uint256 multiplier)
        external
        pure
        returns (uint256)
    {
        return base * multiplier;  // ✅ 自动溢出检查
    }

    // ✅ 安全的减法 - 在确定安全时使用unchecked节省gas
    function subtract(uint256 a, uint256 b) external pure returns (uint256) {
        require(a >= b, "Underflow");  // ✅ 显式检查
        unchecked {
            return a - b;  // ✅ 已经验证安全，使用unchecked节省gas
        }
    }

    // ✅ 安全的批量转账
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts)
        external
        onlyOwner
    {
        require(recipients.length == amounts.length, "Length mismatch");
        require(recipients.length <= 100, "Too many recipients");  // ✅ 限制数量

        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid recipient");
            payable(recipients[i]).transfer(amounts[i]);
        }
    }

    receive() external payable {
        deposit();
    }
}
