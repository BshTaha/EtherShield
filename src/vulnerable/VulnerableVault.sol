// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice INTENTIONALLY VULNERABLE - reentrancy (SWC-107 / CWE-841).
///         Part of the EtherShield lab. Local chain, fake funds only.
/// @dev The bug is the ORDER of operations in withdraw(): the external call
///      happens before the balance is cleared.

contract VulnerableVault {
    /// @notice ETH credited to each depositor.
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    /// @notice Deposit ETH into the vault.
    function deposit() external payable {
        require(msg.value > 0, "VulnerableVault: zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw the caller's full balance
    /// @dev VULNERABLE: Checks -> Interactions -> Effects
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "VulnerableVault: nothing to withdraw");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "VulnerableVault: transfer failed");

        balances[msg.sender] = 0;

        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Balance credited to `account`.
    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    /// @notice Total ETH actually held by the vault.
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
