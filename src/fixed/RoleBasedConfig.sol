// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title RoleBasedConfig
/// @notice The remediated twin of UnprotectedConfig. Same ABI, same behaviour
///         for the honest administrator, but the broken access control
///         (SWC-105 / CWE-284) is closed. EtherShield lab. Local chain, fake
///         funds only.
/// @dev Two layers, mirroring the SecureVault approach:
///      1. THE FIX: ownership is no longer hand-rolled. `transferOwnership` is
///         inherited from OpenZeppelin, already `onlyOwner` - so the guard is
///         not something a maintainer can forget to type. That is the real
///         lesson of the bug: the vulnerable version had a perfectly correct
///         `onlyOwner` modifier and still fell over, because applying it was
///         left to human discipline on every single function.
///      2. DEFENSE IN DEPTH: Ownable2Step makes a handover a two-step
///         handshake - the current owner nominates, the nominee must call
///         `acceptOwnership`. Even a successful nomination to a wrong or
///         hostile address confers zero power until it is accepted, and the
///         owner can cancel by nominating address(0).
///
///      WHY "RoleBased" WITH A SINGLE OWNER: this contract has exactly one
///      privilege tier - every guarded action is equally administrative - so a
///      single owner role is the honest model, and OZ's audited implementation
///      beats a bespoke one. If the privileges were ever split (a pauser who
///      cannot touch the treasury, a treasurer who cannot change fees), the
///      move would be OZ `AccessControl` with distinct roles rather than more
///      hand-written modifiers.
///
///      DELIBERATELY UNCHANGED: `sweep(address to)` still lets the owner send
///      the treasury anywhere. That is a trust/centralization property, not an
///      access-control bug, and keeping it identical is what makes the
///      before/after comparison about one variable only.
contract RoleBasedConfig is Ownable2Step {
    /// @notice Where protocol fees are routed.
    address public feeRecipient;
    /// @notice Fee in basis points (1% = 100).
    uint256 public feeBps;
    /// @notice When true, the protocol is halted.
    bool public paused;

    event FeeRecipientUpdated(address indexed previousRecipient, address indexed newRecipient);
    event FeeBpsUpdated(uint256 previousBps, uint256 newBps);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event Deposited(address indexed from, uint256 amount);
    event Swept(address indexed to, uint256 amount);

    /// @dev `owner` is set by Ownable's constructor, which also rejects the zero
    ///      address - so there is no window where the contract is unowned.
    constructor(address _feeRecipient, uint256 _feeBps) Ownable(msg.sender) {
        require(_feeRecipient != address(0), "RoleBasedConfig: zero recipient");
        require(_feeBps <= 10_000, "RoleBasedConfig: fee too high");
        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
    }

    /// @notice Redirect protocol fees.
    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "RoleBasedConfig: zero recipient");
        emit FeeRecipientUpdated(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    /// @notice Update the fee.
    function setFeeBps(uint256 newBps) external onlyOwner {
        require(newBps <= 10_000, "RoleBasedConfig: fee too high");
        emit FeeBpsUpdated(feeBps, newBps);
        feeBps = newBps;
    }

    /// @notice Halt the protocol.
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resume the protocol.
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Fund the treasury (stands in for accrued protocol fees).
    /// @dev Intentionally open to anyone, exactly as in the vulnerable twin:
    ///      funding a treasury is not a privileged action.
    function deposit() external payable {
        require(msg.value > 0, "RoleBasedConfig: zero deposit");
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Send the entire treasury to `to`.
    /// @dev Still `onlyOwner` - unchanged from the vulnerable twin, where this
    ///      guard was never the problem. The exploit reached it by becoming the
    ///      owner first; with that route closed, the guard holds.
    function sweep(address to) external onlyOwner {
        require(to != address(0), "RoleBasedConfig: zero recipient");
        uint256 amount = address(this).balance;
        // Log before the interaction: `forge lint` flags an event emitted after
        // an external call (reentrancy-events), because a re-entrant callee can
        // reorder logs that off-chain consumers trust. If the call fails the
        // whole transaction reverts and this log disappears with it, so moving
        // it earlier costs nothing.
        emit Swept(to, amount);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "RoleBasedConfig: sweep failed");
    }

    /// @notice Total ETH held by the treasury.
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
