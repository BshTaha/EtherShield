// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title SecureVault
/// @notice The remediated twin of VulnerableVault. Same ABI, same behaviour
///         for honest users, but the reentrancy (SWC-107 / CWE-841) is closed.
///         EtherShield lab. Local chain, fake funds only.
/// @dev Two independent layers, either of which defeats the exploit on its own:
///      1. Checks-Effects-Interactions: the balance is zeroed BEFORE the
///         external call, so a re-entrant withdraw() sees a 0 balance and the
///         `amount > 0` check reverts the nested call.
///      2. OpenZeppelin ReentrancyGuard: `nonReentrant` reverts any call that
///         re-enters a guarded function within the same transaction, before a
///         single line of its body runs.
///      Layer 1 is the fix. Layer 2 is defense-in-depth: it still protects any
///      future function a maintainer adds and wires up incorrectly.
contract SecureVault is ReentrancyGuard {
    /// @notice ETH credited to each depositor.
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    /// @notice Deposit ETH into the vault.
    function deposit() external payable {
        require(msg.value > 0, "SecureVault: zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw the caller's full balance.
    /// @dev SECURE: Checks -> Effects -> Interactions, under nonReentrant.
    ///      The only line order that changed from VulnerableVault is that the
    ///      state write now precedes the external call. That single swap is the
    ///      whole remediation; the guard is belt-and-suspenders.
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "SecureVault: nothing to withdraw");

        // Effects first: the credit is gone before control ever leaves this
        // contract, so there is nothing left to drain on re-entry.
        balances[msg.sender] = 0;

        // Interaction last.
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "SecureVault: transfer failed");

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
