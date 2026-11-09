// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {RoleBasedConfig} from "../fixed/RoleBasedConfig.sol";

/// @title RoleBasedConfigAttacker
/// @notice The same exploit as AccessControlAttacker, re-pointed at the fixed
///         contract. EtherShield lab, local chain only.
/// @dev Why this file exists at all: AccessControlAttacker is typed
///      `UnprotectedConfig` in its constructor and immutable state, so it
///      cannot be aimed at RoleBasedConfig without editing it. Rather than
///      weaken the original exploit, this is a parallel attacker with
///      IDENTICAL attack logic and only the target type changed - so a failure
///      here is attributable to the fix, not to a different attack. (Same
///      reasoning as SecureVaultAttacker in vuln 1. The alternative is a shared
///      interface both configs implement; that refactor would let one attacker
///      serve both, at the cost of touching already-proven code.)
///
///      Expected result: attack() reverts at step 1 with
///      Ownable.OwnableUnauthorizedAccount(address(this)) and the treasury is
///      untouched. claimOwnership() exists to prove the SECOND door is locked
///      too: even if a transfer were somehow initiated, only the nominated
///      address can accept it.
contract RoleBasedConfigAttacker {
    RoleBasedConfig public immutable config;
    address public immutable owner;

    event AttackerStarted(address indexed target);
    event Hijacked(address indexed newOwner);
    event Drained(uint256 amount);

    error NotOwner();
    error PayoutFailed();

    constructor(RoleBasedConfig _config) {
        config = _config;
        owner = msg.sender;
    }

    /// @notice Byte-for-byte the attack that drained UnprotectedConfig.
    /// @dev Step 1 now reverts, so the whole transaction reverts and step 2 is
    ///      never reached - nothing partial, nothing stolen.
    function attack() external {
        emit AttackerStarted(address(config));

        // Step 1: the door that used to be unlocked. transferOwnership is now
        // inherited and onlyOwner, so this reverts for a stranger.
        config.transferOwnership(address(this));
        emit Hijacked(address(this));

        // Step 2: unreachable. Kept so the two attackers stay comparable.
        uint256 amount = config.totalAssets();
        config.sweep(address(this));
        emit Drained(amount);
    }

    /// @notice Try to accept an ownership transfer we were never nominated for.
    /// @dev The Ownable2Step half of the fix: reverts with
    ///      OwnableUnauthorizedAccount unless pendingOwner() == address(this).
    function claimOwnership() external {
        config.acceptOwnership();
    }

    /// @notice Accept any swept treasury (never called in the fixed scenario).
    receive() external payable {}

    /// @notice Forward stolen ETH to the attacker's EOA.
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
