// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SecureVault} from "../fixed/SecureVault.sol";

/// @title SecureVaultAttacker
/// @notice The exact same exploit as ReentrancyAttacker, re-pointed at the
///         fixed vault, so the test is apples-to-apples: identical attack,
///         opposite outcome. EtherShield lab, local chain only.
/// @dev Against SecureVault the re-entrant withdraw() in receive() reverts
///      (the nonReentrant guard fires first; CEI would stop it anyway). That
///      revert propagates into the vault's low-level send, flips `ok` to false,
///      and unwinds the ENTIRE attack transaction. The attacker nets nothing,
///      not even its own deposit back within attack().
contract SecureVaultAttacker {
    SecureVault public immutable vault;
    address public immutable owner;

    /// @notice Amount the attacker tried to withdraw per re-entrant call.
    uint256 public unit;
    /// @notice How many times this contract tried to re-enter withdraw().
    uint256 public callCount;

    event AttackerStarted(uint256 unit);
    event Reentered(uint256 depth, uint256 vaultBalance);

    error NotOwner();
    error PayoutFailed();

    constructor(SecureVault _vault) {
        vault = _vault;
        owner = msg.sender;
    }

    /// @notice Deposit `msg.value` then attempt to drain in one transaction.
    ///         Reverts against SecureVault.
    function attack() external payable {
        require(msg.value > 0, "SecureVaultAttacker: fund the attack");

        unit = msg.value;
        callCount = 1;
        emit AttackerStarted(unit);

        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    /// @notice Re-entry point. Against the fixed vault this nested withdraw()
    ///         reverts, which is what breaks the attack.
    receive() external payable {
        if (address(vault).balance >= unit) {
            callCount++;
            emit Reentered(callCount, address(vault).balance);
            vault.withdraw();
        }
    }

    /// @notice Forward any held ETH to the attacker's EOA.
    function collect() external {
        if (msg.sender != owner) revert NotOwner();
        (bool ok,) = owner.call{value: address(this).balance}("");
        if (!ok) revert PayoutFailed();
    }

    /// @notice ETH currently held by this exploit contract.
    function loot() external view returns (uint256) {
        return address(this).balance;
    }
}
