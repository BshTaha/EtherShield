// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SecureVault} from "../src/fixed/SecureVault.sol";
import {SecureVaultAttacker} from "../src/attackers/SecureVaultAttacker.sol";

/// @notice A minimal honest-looking depositor that tries ONE re-entrant
///         withdraw() from inside its receive(), but catches the result instead
///         of cascading. Lets the test read the exact revert the guard throws
///         while the legitimate outer withdraw still completes.
contract GuardProbe {
    SecureVault public immutable vault;

    bool public reentryAttempted;
    bool public reentryReverted;
    bytes4 public reentryRevertSelector;

    constructor(SecureVault _vault) {
        vault = _vault;
    }

    function depositAndWithdraw() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        // Re-enter exactly once, during the vault's mid-withdrawal callback.
        if (!reentryAttempted) {
            reentryAttempted = true;
            try vault.withdraw() {
            // Reached only if the guard failed to stop re-entry.
            }
            catch (bytes memory reason) {
                reentryReverted = true;
                reentryRevertSelector = bytes4(reason);
            }
        }
    }
}

/// @title SecureVaultTest
/// @notice Proves the remediation: the identical reentrancy exploit that drains
///         VulnerableVault steals nothing from SecureVault, honest users are
///         unaffected, and the vault stays solvent (assets == ledger).
/// @dev Local chain, fake funds only.
contract SecureVaultTest is Test {
    SecureVault internal vault;
    SecureVaultAttacker internal attacker;

    address internal attackerEoa = makeAddr("attackerEoa");
    address[3] internal depositors;

    uint256 internal constant DEPOSIT = 1 ether;

    function setUp() public {
        vault = new SecureVault();

        // Same opening position as the exploit test: 3 honest ETH in the vault.
        for (uint256 i = 0; i < depositors.length; i++) {
            depositors[i] = makeAddr(string.concat("depositor", vm.toString(i)));
            vm.deal(depositors[i], DEPOSIT);
            vm.prank(depositors[i]);
            vault.deposit{value: DEPOSIT}();
        }

        vm.deal(attackerEoa, DEPOSIT);
        // prank covers the constructor call: attacker.owner() must be the EOA.
        vm.prank(attackerEoa);
        attacker = new SecureVaultAttacker(vault);
    }

    /// @notice Baseline, identical to the vulnerable suite's. Same starting line.
    function test_setupIsSane() public view {
        assertEq(vault.totalAssets(), 3 * DEPOSIT, "vault should hold 3 ETH");
        for (uint256 i = 0; i < depositors.length; i++) {
            assertEq(vault.balanceOf(depositors[i]), DEPOSIT, "each depositor credited 1 ETH");
        }
        assertEq(attacker.loot(), 0, "attacker starts empty");
        assertEq(attacker.owner(), attackerEoa, "EOA owns the exploit");
        assertEq(address(attacker.vault()), address(vault), "exploit points at the secure vault");
    }

    /// @notice THE FIX, PROVEN: the same attack that drained VulnerableVault now
    ///         reverts, and every wei is exactly where it started.
    function test_reentrantAttackRevertsAndStealsNothing() public {
        vm.prank(attackerEoa);
        // The nested withdraw() reverts; that bubbles into the vault's send,
        // trips require(ok), and unwinds the whole transaction.
        vm.expectRevert("SecureVault: transfer failed");
        attacker.attack{value: DEPOSIT}();

        // Nothing moved. The attack reverted, so even its own deposit rolled back.
        assertEq(vault.totalAssets(), 3 * DEPOSIT, "vault still holds exactly 3 ETH");
        assertEq(attacker.loot(), 0, "attacker stole nothing");
        assertEq(attackerEoa.balance, DEPOSIT, "attacker keeps only its original 1 ETH");
        for (uint256 i = 0; i < depositors.length; i++) {
            assertEq(vault.balanceOf(depositors[i]), DEPOSIT, "depositor credit untouched");
        }
    }

    /// @notice The guard, caught in the act: a re-entrant withdraw() reverts with
    ///         ReentrancyGuardReentrantCall, while the legitimate withdraw that
    ///         triggered it still settles. This is the mechanism, isolated.
    function test_guardRejectsReentryWithSelector() public {
        GuardProbe probe = new GuardProbe(vault);
        vm.deal(address(this), DEPOSIT);

        uint256 vaultBefore = vault.totalAssets();
        probe.depositAndWithdraw{value: DEPOSIT}();

        assertTrue(probe.reentryAttempted(), "probe tried to re-enter");
        assertTrue(probe.reentryReverted(), "the re-entrant withdraw was rejected");
        assertEq(
            probe.reentryRevertSelector(),
            ReentrancyGuard.ReentrancyGuardReentrantCall.selector,
            "rejected specifically by the nonReentrant guard"
        );
        // The honest outer withdrawal still completed: probe got its 1 ETH back
        // and the vault is back to its pre-probe balance.
        assertEq(address(probe).balance, DEPOSIT, "probe's legitimate withdrawal settled");
        assertEq(vault.totalAssets(), vaultBefore, "vault returned to its prior balance");
        assertEq(vault.balanceOf(address(probe)), 0, "probe credit zeroed once");
    }

    /// @notice Happy path intact: Checks-Effects-Interactions did not break an
    ///         ordinary withdrawal.
    function test_honestDepositorCanWithdraw() public {
        vm.prank(depositors[0]);
        vault.withdraw();

        assertEq(depositors[0].balance, DEPOSIT, "depositor received their 1 ETH");
        assertEq(vault.balanceOf(depositors[0]), 0, "depositor credit cleared");
        assertEq(vault.totalAssets(), 2 * DEPOSIT, "vault down to the other 2 ETH");
    }

    /// @notice Solvency, the property the vulnerable vault lost: every depositor
    ///         can fully exit and the vault empties to exactly zero. Assets always
    ///         equalled the ledger.
    function test_allDepositorsCanFullyExit() public {
        for (uint256 i = 0; i < depositors.length; i++) {
            vm.prank(depositors[i]);
            vault.withdraw();
            assertEq(depositors[i].balance, DEPOSIT, "each depositor recovered 1 ETH");
        }
        assertEq(vault.totalAssets(), 0, "vault empties cleanly to zero");
    }

    /// @notice The mirror of the vulnerable suite's fuzz test: whatever the
    ///         attacker stakes, the attack reverts whole and the vault keeps
    ///         exactly what the honest depositors put in. There is no stake that
    ///         gets anything out.
    function testFuzz_attackRevertsForAnyStake(uint96 stake) public {
        uint256 unit = bound(uint256(stake), 0.1 ether, 1 ether);

        vm.deal(attackerEoa, unit);
        vm.prank(attackerEoa);
        vm.expectRevert("SecureVault: transfer failed");
        attacker.attack{value: unit}();

        assertEq(vault.totalAssets(), 3 * DEPOSIT, "vault still holds exactly 3 ETH");
        assertEq(attacker.loot(), 0, "exploit contract got nothing");
        assertEq(attackerEoa.balance, unit, "attacker keeps only its own stake");
        for (uint256 i = 0; i < depositors.length; i++) {
            assertEq(vault.balanceOf(depositors[i]), DEPOSIT, "depositor credit untouched");
        }
    }
}
