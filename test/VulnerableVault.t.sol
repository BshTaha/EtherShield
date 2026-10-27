// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableVault} from "../src/vulnerable/VulnerableVault.sol";
import {ReentrancyAttacker} from "../src/attackers/ReentrancyAttacker.sol";

/// @title VulnerableVaultTest
/// @notice Proves the reentrancy (SWC-107) in VulnerableVault is exploitable.
/// @dev Local chain, fake funds only. The exploit runs in ONE transaction:
///      attack() -> withdraw() -> receive() -> withdraw() -> ...
contract VulnerableVaultTest is Test {
    VulnerableVault internal vault;
    ReentrancyAttacker internal attacker;

    /// @dev The human behind the exploit contract. Owns it, collects the loot.
    address internal attackerEoa = makeAddr("attackerEoa");
    /// @dev Honest users whose ETH gets stolen.
    address[3] internal depositors;

    uint256 internal constant DEPOSIT = 1 ether;

    function setUp() public {
        vault = new VulnerableVault();

        // 3 honest depositors x 1 ETH = the 3 ETH the attacker will steal.
        for (uint256 i = 0; i < depositors.length; i++) {
            // string.concat + vm.toString, NOT abi.encodePacked: encodePacked
            // null-pads the uint to 32 bytes and ruins the trace labels.
            depositors[i] = makeAddr(string.concat("depositor", vm.toString(i)));
            vm.deal(depositors[i], DEPOSIT);
            vm.prank(depositors[i]);
            vault.deposit{value: DEPOSIT}();
        }

        vm.deal(attackerEoa, DEPOSIT);
        // prank covers exactly ONE next call, so this one lands on the
        // constructor: attacker.owner() must be the EOA, not this test contract.
        vm.prank(attackerEoa);
        attacker = new ReentrancyAttacker(vault);
    }

    /// @notice Baseline. If this fails, every other result below is meaningless.
    function test_setupIsSane() public view {
        assertEq(vault.totalAssets(), 3 * DEPOSIT, "vault should hold 3 ETH");
        for (uint256 i = 0; i < depositors.length; i++) {
            assertEq(vault.balanceOf(depositors[i]), DEPOSIT, "each depositor credited 1 ETH");
        }
        assertEq(attacker.loot(), 0, "attacker starts empty");
        assertEq(attacker.callCount(), 0, "no withdraw calls yet");
        assertEq(attacker.owner(), attackerEoa, "EOA owns the exploit");
        assertEq(address(attacker.vault()), address(vault), "exploit points at the vault");
    }

    /// @notice THE EXPLOIT: 1 ETH in, 4 ETH out, single transaction.
    function test_reentrancyDrainsVault() public {
        vm.prank(attackerEoa);
        attacker.attack{value: DEPOSIT}();

        assertEq(vault.totalAssets(), 0, "vault fully drained");
        assertEq(attacker.loot(), 4 * DEPOSIT, "attacker holds its 1 ETH + 3 stolen");
        // 1 outer withdraw + 3 re-entrant ones; the 4th re-entry is refused
        // by the `balance >= unit` guard because the vault is empty.
        assertEq(attacker.callCount(), 4, "withdraw() ran 4 times in one tx");
        // balances[attacker] is written once, AFTER the recursion unwinds.
        assertEq(vault.balanceOf(address(attacker)), 0, "attacker credit zeroed once");
        // The damage, in one line: the ledger still owes 1 ETH per depositor,
        // but the ETH backing those credits is gone. Accounting != solvency.
        assertEq(vault.balanceOf(depositors[0]), DEPOSIT, "stale credit: ledger still owes 1 ETH");
        assertEq(attackerEoa.balance, 0, "loot is still in the exploit contract");
    }

    /// @notice The victim's loss, made concrete.
    function test_honestDepositorCannotWithdrawAfterAttack() public {
        vm.prank(attackerEoa);
        attacker.attack{value: DEPOSIT}();

        vm.prank(depositors[0]);
        // The vault holds 0 wei, so the low-level .call cannot forward 1 ETH:
        // ok == false -> require trips. String revert -> string overload.
        vm.expectRevert("VulnerableVault: transfer failed");
        vault.withdraw();
    }

    /// @notice Cash-out path: loot leaves the exploit contract for the EOA.
    function test_collectSendsLootToOwner() public {
        vm.prank(attackerEoa);
        attacker.attack{value: DEPOSIT}();

        vm.prank(attackerEoa);
        attacker.collect();

        assertEq(attackerEoa.balance, 4 * DEPOSIT, "EOA cashed out 4 ETH");
        assertEq(attacker.loot(), 0, "exploit contract emptied");
    }

    /// @notice Even the exploit has access control. Custom error -> selector overload.
    function test_collectRevertsForNonOwner() public {
        vm.prank(attackerEoa);
        attacker.attack{value: DEPOSIT}();

        vm.prank(depositors[0]);
        vm.expectRevert(ReentrancyAttacker.NotOwner.selector);
        attacker.collect();
    }
}
