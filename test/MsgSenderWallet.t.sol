// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {MsgSenderWallet} from "../src/fixed/MsgSenderWallet.sol";
import {MsgSenderWalletAttacker} from "../src/attackers/MsgSenderWalletAttacker.sol";

/// @title MsgSenderWalletTest
/// @notice Proves MsgSenderWallet defeats the tx.origin phishing attack that
///         empties TxOriginWallet, and that it keeps every legitimate behaviour
///         the vulnerable twin had.
/// @dev Written to mirror test/TxOriginWallet.t.sol test for test, in the same
///      order, so the two files can be read side by side: each exploit there has
///      a named counterpart here. Local chain, fake funds only.
///
///      Note that the two-argument `vm.prank(sender, origin)` is still used
///      throughout even though this wallet never reads `tx.origin`. That is the
///      point: the victim's origin is set exactly as it was in the attack that
///      worked, and now it buys the attacker nothing.
contract MsgSenderWalletTest is Test {
    MsgSenderWallet internal wallet;
    MsgSenderWalletAttacker internal attacker;

    address internal victim = makeAddr("victim");
    address internal attackerEoa = makeAddr("attackerEoa");
    address internal bystander = makeAddr("bystander");
    address internal recovery = makeAddr("recovery");

    uint256 internal constant FUNDS = 3 ether;
    uint256 internal constant POCKET = 1 ether;

    function setUp() public {
        vm.prank(victim);
        wallet = new MsgSenderWallet();

        vm.deal(victim, FUNDS + POCKET);
        vm.prank(victim);
        wallet.deposit{value: FUNDS}();

        vm.prank(attackerEoa);
        attacker = new MsgSenderWalletAttacker(wallet);
    }

    /// @notice Baseline, identical to the vulnerable suite's.
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

    /// @notice The fix did not break the wallet. Mirror of the vulnerable
    ///         suite's test of the same name - same call, same expectations.
    function test_ownerCanUseTheirOwnWallet() public {
        vm.prank(victim, victim);
        wallet.transferTo(bystander, 1 ether);

        assertEq(bystander.balance, 1 ether, "bystander received the transfer");
        assertEq(wallet.balance(), FUNDS - 1 ether, "wallet debited");
        assertEq(wallet.owner(), victim, "owner unchanged");
    }

    /// @notice Strangers are still rejected, as they were before. The fix is not
    ///         "add a guard" - there already was one - so this must not change.
    function test_strangerCannotAttackAlone() public {
        vm.startPrank(attackerEoa, attackerEoa);

        vm.expectRevert("MsgSenderWallet: not owner");
        wallet.sweep(attackerEoa);

        vm.expectRevert("MsgSenderWallet: not owner");
        wallet.transferTo(attackerEoa, 1 ether);

        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.claimReward();

        vm.stopPrank();

        assertEq(wallet.balance(), FUNDS, "wallet untouched");
        assertEq(attacker.loot(), 0, "nothing stolen");
    }

    /// @notice The mirror of test_onlyTxOriginGuardedCallsAreHijackable, and the
    ///         heart of the fix: with the victim as transaction origin - the
    ///         exact condition that drained the vulnerable wallet - EVERY
    ///         privileged call now rejects the exploit contract. There is no
    ///         longer a hijackable half.
    function test_everyPrivilegedCallNowChecksTheCaller() public {
        vm.prank(victim, victim);
        wallet.setRecoveryAddress(recovery);

        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.tryTransfer(1 ether);

        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.tryHijackRecovery();

        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not recovery");
        attacker.tryRecoverOwnership();

        // The recovery door, attempted end to end, fails at the nomination step
        // because setRecoveryAddress now goes through the same modifier.
        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.claimOwnershipByRecovery();

        assertEq(wallet.balance(), FUNDS, "not a wei moved");
        assertEq(wallet.recoveryAddress(), recovery, "recovery nominee unchanged");
        assertEq(wallet.owner(), victim, "owner unchanged");
    }

    /// @notice The attack that emptied TxOriginWallet. The victim takes the same
    ///         lure in the same way, and their transaction reverts instead.
    function test_phishingAttemptRevertsAndStealsNothing() public {
        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.claimReward();

        assertEq(wallet.balance(), FUNDS, "wallet intact");
        assertEq(attacker.loot(), 0, "exploit got nothing");
        assertFalse(attacker.hijacked(), "no attack succeeded");
        assertEq(attacker.stolen(), 0, "nothing recorded as stolen");
    }

    /// @notice Mirror of test_victimKeepsTitleButLosesMoney: there, the victim
    ///         kept the title and lost the money. Here they keep both, and -
    ///         unlike there - their own next transfer still goes through.
    function test_ownerKeepsTitleAndMoney() public {
        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.claimReward();

        assertEq(wallet.owner(), victim, "still the owner");

        vm.prank(victim, victim);
        wallet.transferTo(bystander, 1 ether);

        assertEq(bystander.balance, 1 ether, "the honest transfer was paid");
        assertEq(wallet.balance(), FUNDS - 1 ether, "and only that left the wallet");
    }

    /// @notice The drive-by variant is closed too, and it fails LOUDLY: the
    ///         sweep inside `receive()` reverts, which reverts the victim's whole
    ///         ETH transfer. They keep their tip.
    function test_driveByEthTransferNoLongerDrains() public {
        vm.prank(victim, victim);
        (bool ok,) = address(attacker).call{value: 0.1 ether}("");

        assertFalse(ok, "the victim's bare ETH send reverted with the attack");
        assertEq(wallet.balance(), FUNDS, "wallet intact");
        assertEq(attacker.loot(), 0, "exploit holds neither the wallet nor the tip");
        assertEq(victim.balance, POCKET, "the victim still has their own ETH");
    }

    /// @notice Mirror of test_lootIsExtractable: there is nothing to extract.
    ///         `collect()` succeeds but pays out zero, so the failure is a real
    ///         absence of funds rather than ETH stuck inside the exploit.
    function test_thereIsNoLootToExtract() public {
        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.claimReward();

        uint256 before = attackerEoa.balance;
        vm.prank(attackerEoa);
        attacker.collect();

        assertEq(attackerEoa.balance, before, "attacker's EOA gained nothing");
        assertEq(attacker.loot(), 0, "exploit contract is empty");
    }

    /// @notice The recovery feature still works end to end for the people it was
    ///         built for. Routing it through onlyOwner closed the attack without
    ///         removing the capability.
    function test_honestRecoveryStillWorks() public {
        vm.prank(victim, victim);
        wallet.setRecoveryAddress(recovery);
        assertEq(wallet.recoveryAddress(), recovery, "nominee recorded");

        vm.prank(recovery, recovery);
        wallet.recoverOwnership();
        assertEq(wallet.owner(), recovery, "nominee took over");

        // And the new owner really controls the funds.
        vm.prank(recovery, recovery);
        wallet.sweep(recovery);
        assertEq(recovery.balance, FUNDS, "new owner swept their own wallet");
        assertEq(wallet.balance(), 0, "wallet emptied by its legitimate owner");
    }

    /// @notice Mirror of testFuzz_phishingTakesWhateverIsThere: the fix holds
    ///         for any balance, not just the 3 ETH the worked example uses.
    function testFuzz_phishingFailsForAnyBalance(uint96 extra) public {
        uint256 topUp = bound(uint256(extra), 0, 100 ether);
        vm.deal(victim, victim.balance + topUp);
        if (topUp > 0) {
            vm.prank(victim, victim);
            wallet.deposit{value: topUp}();
        }

        uint256 held = wallet.balance();

        vm.prank(victim, victim);
        vm.expectRevert("MsgSenderWallet: not owner");
        attacker.claimReward();

        assertEq(wallet.balance(), held, "balance untouched whatever its size");
        assertEq(attacker.loot(), 0, "exploit took nothing");
    }
}
