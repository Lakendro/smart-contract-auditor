// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * @title VulnerableContract
 * @dev 这是一个包含多个安全漏洞的示例合约，用于测试审计工具
 * ⚠️ 不要在生产环境中使用此合约！
 */
contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed from, uint256 amount);
    event Withdrawal(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;  // ❌ 没有验证msg.sender是否为有效地址
    }

    // 存款函数
    function deposit() external payable {
        balances[msg.sender] += msg.value;  // ❌ Solidity 0.8之前没有溢出检查
        emit Deposit(msg.sender, msg.value);
    }

    // ❌ 重入攻击漏洞 - 外部调用后更新状态
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ❌ 先执行外部调用
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // ❌ 后更新状态 - 容易被重入攻击
        balances[msg.sender] -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    // ❌ 使用tx.origin进行授权 - 钓鱼攻击风险
    function emergencyWithdraw() external {
        require(tx.origin == owner, "Not authorized");  // ❌ 使用tx.origin不安全
        payable(owner).transfer(address(this).balance);
    }

    // ❌ 缺失权限修饰器的敏感函数
    function mint(address to, uint256 amount) external {
        // ❌ 没有onlyOwner修饰器，任何人都可以mint
        balances[to] += amount;  // ❌ 潜在溢出
    }

    // ❌ 缺失权限修饰器的敏感函数
    function setOwner(address newOwner) external {
        // ❌ 没有权限检查
        owner = newOwner;
    }

    // ❌ 可构造函数参数未验证
    function unsafeFunction(address target, uint256 value) external {
        // ❌ 没有验证target和value
        payable(target).transfer(value);
    }

    // ❌ 乘法可能导致溢出
    function calculateReward(uint256 base, uint256 multiplier) external pure returns (uint256) {
        // ❌ Solidity 0.7.0需要SafeMath保护
        return base * multiplier;
    }

    // ❌ 减法可能导致下溢
    function subtract(uint256 a, uint256 b) external pure returns (uint256) {
        // ❌ 没有检查a >= b
        return a - b;
    }

    receive() external payable {
        deposit();
    }
}
