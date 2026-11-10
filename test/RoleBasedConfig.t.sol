// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {RoleBasedConfig} from "../src/fixed/RoleBasedConfig.sol";
import {RoleBasedConfigAttacker} from "../src/attackers/RoleBasedConfigAttacker.sol";

/// @title RoleBasedConfigTest
/// @notice The counter-proof to UnprotectedConfig.t.sol: the identical
///         hijack-then-drain attack now fails, the treasury survives, and the
///         honest administrator loses nothing.
/// @dev Deliberately mirrors the vulnerable suite test-for-test, so the two
///         files can be read side by side in the demo. Local chain, fake funds.
contract RoleBasedConfigTest is Test {
    RoleBasedConfig internal config;
    RoleBasedConfigAttacker internal attacker;

    /// @dev The legitimate administrator (deploys the contract, owns it).
    address internal admin = makeAddr("admin");
    /// @dev Where fees are routed. Just a bystander here.
    address internal feeRecipient = makeAddr("feeRecipient");
    /// @dev The human behind the exploit contract.
    address internal attackerEoa = makeAddr("attackerEoa");
    /// @dev A legitimate successor, used for the honest-handover test.
    address internal newAdmin = makeAddr("newAdmin");

    uint256 internal constant TREASURY = 3 ether;
    uint256 internal constant FEE_BPS = 100; // 1%

    function setUp() public {
        // Same crime scene as the vulnerable suite: same balances, same actors.
        vm.prank(admin);
        config = new RoleBasedConfig(feeRecipient, FEE_BPS);

        vm.deal(admin, TREASURY);
        vm.prank(admin);
        config.deposit{value: TREASURY}();

        vm.prank(attackerEoa);
        attacker = new RoleBasedConfigAttacker(config);
    }

    /// @notice Baseline. Identical to the vulnerable suite, plus the new
    ///         pendingOwner slot, which must start empty.
    function test_setupIsSane() public view {
        assertEq(config.owner(), admin, "admin owns the config");
        assertEq(config.pendingOwner(), address(0), "no transfer pending");
        assertEq(config.feeRecipient(), feeRecipient, "fee recipient set");
        assertEq(config.feeBps(), FEE_BPS, "fee bps set");
        assertEq(config.totalAssets(), TREASURY, "treasury holds 3 ETH");
        assertEq(attacker.owner(), attackerEoa, "EOA owns the exploit");
        assertEq(address(attacker.config()), address(config), "exploit points at the fix");
    }

    /// @notice THE COUNTER-PROOF: the exact attack that drained the vulnerable
    ///         twin now reverts at step 1, and nothing moves.
    /// @dev The revert carries the caller in its payload, so the assertion is
    ///      specific about WHO was rejected: the exploit contract, not its EOA.
    ///      This is the argument-bearing form of expectRevert - a bare selector
    ///      would also pass if the wrong account were rejected.
    function test_hijackRevertsAndStealsNothing() public {
        vm.prank(attackerEoa);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(attacker)));
        attacker.attack();

        assertEq(config.owner(), admin, "admin is still the owner");
        assertEq(config.pendingOwner(), address(0), "nothing was even nominated");
        assertEq(config.totalAssets(), TREASURY, "treasury untouched");
        assertEq(attacker.loot(), 0, "exploit stole nothing");
    }

    /// @notice The direct mirror of test_onlyTransferOwnershipIsUnguarded: the
    ///         gap is closed, so now EVERY privileged entry point rejects a
    ///         stranger - including transferOwnership.
    function test_everyPrivilegedCallNowRejectsStranger() public {
        bytes memory rejected = abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attackerEoa);

        vm.startPrank(attackerEoa);
        vm.expectRevert(rejected);
        config.sweep(attackerEoa);
        vm.expectRevert(rejected);
        config.setFeeRecipient(attackerEoa);
        vm.expectRevert(rejected);
        config.setFeeBps(0);
        vm.expectRevert(rejected);
        config.pause();
        // The line that used to succeed.
        vm.expectRevert(rejected);
        config.transferOwnership(attackerEoa);
        vm.stopPrank();

        assertEq(config.owner(), admin, "ownership never moved");
    }

    /// @notice The second layer, in isolation: acceptOwnership is not a public
    ///         back door. Only the nominated address can take the role.
    function test_acceptOwnershipRejectsNonNominatedCaller() public {
        vm.prank(attackerEoa);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(attacker)));
        attacker.claimOwnership();

        assertEq(config.owner(), admin, "admin is still the owner");
    }

    /// @notice What Ownable2Step buys beyond the missing modifier: a nomination
    ///         alone confers no power. Ownership only moves on acceptance.
    function test_honestHandoverRequiresAcceptance() public {
        vm.expectEmit(true, true, false, true, address(config));
        emit Ownable2Step.OwnershipTransferStarted(admin, newAdmin);
        vm.prank(admin);
        config.transferOwnership(newAdmin);

        // Nominated, but powerless.
        assertEq(config.pendingOwner(), newAdmin, "successor is pending");
        assertEq(config.owner(), admin, "admin is STILL the owner");
        vm.prank(newAdmin);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, newAdmin));
        config.sweep(newAdmin);

        // Acceptance completes the handover.
        vm.prank(newAdmin);
        config.acceptOwnership();
        assertEq(config.owner(), newAdmin, "successor accepted and now owns it");
        assertEq(config.pendingOwner(), address(0), "pending slot cleared");
    }

    /// @notice A mistaken nomination is recoverable: the owner cancels it by
    ///         nominating address(0). Impossible to undo in a one-step model.
    function test_pendingTransferCanBeCancelled() public {
        vm.startPrank(admin);
        config.transferOwnership(attackerEoa);
        assertEq(config.pendingOwner(), attackerEoa, "mistake is pending");
        config.transferOwnership(address(0));
        vm.stopPrank();

        assertEq(config.pendingOwner(), address(0), "nomination cancelled");
        vm.prank(attackerEoa);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attackerEoa));
        config.acceptOwnership();
        assertEq(config.owner(), admin, "admin kept the contract");
    }

    /// @notice The fix did not break the honest path: the real owner can still
    ///         configure the protocol and move the treasury.
    function test_ownerCanStillConfigureAndSweep() public {
        vm.startPrank(admin);
        config.setFeeBps(250);
        config.pause();
        config.unpause();
        config.sweep(feeRecipient);
        vm.stopPrank();

        assertEq(config.feeBps(), 250, "fee updated by the owner");
        assertFalse(config.paused(), "unpaused again");
        assertEq(config.totalAssets(), 0, "treasury emptied deliberately");
        assertEq(feeRecipient.balance, TREASURY, "3 ETH landed where the owner sent it");
    }

    /// @notice The mirror: no address at all can take ownership of the fixed
    ///         contract. Ownable rejects every caller but the owner, and it
    ///         names the rejected account in the error - so this also proves the
    ///         RIGHT caller was rejected, not merely that something reverted.
    function testFuzz_noStrangerCanSeizeOwnership(address stranger) public {
        vm.assume(stranger != admin);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        config.transferOwnership(stranger);

        assertEq(config.owner(), admin, "owner unchanged");
        assertEq(config.pendingOwner(), address(0), "no nomination recorded");
        assertEq(config.totalAssets(), TREASURY, "treasury intact");
    }

    /// @notice TRIAGED NON-ISSUE, pinned here so it is not rediscovered as a
    ///         bug. OpenZeppelin's Ownable2Step compares `pendingOwner()` with
    ///         `msg.sender`, and `pendingOwner()` is address(0) until someone is
    ///         nominated - so a call whose sender IS address(0) passes the check
    ///         and takes ownership, leaving the contract ownerless.
    /// @dev Why it is not a vulnerability: no transaction can originate from
    ///      address(0). It has no private key, and the EVM never sets msg.sender
    ///      to it for a real call. The only way to produce this is vm.prank,
    ///      which is why the invariant handler in
    ///      test/invariant/ConfigOwnershipInvariant.t.sol excludes address(0)
    ///      from its hostile senders - it found this first, and reported it as a
    ///      broken invariant. If belt-and-braces hardening were ever wanted, an
    ///      override requiring `pendingOwner() != address(0)` would close it.
    function test_zeroAddressAcceptanceIsAnArtefactNotAFinding() public {
        assertEq(config.pendingOwner(), address(0), "no nomination outstanding");

        vm.prank(address(0));
        config.acceptOwnership();

        assertEq(config.owner(), address(0), "ownership moved to the zero address");
        assertEq(config.pendingOwner(), address(0), "pending slot cleared");

        // And the consequence, for the record: the config is now ownerless, so
        // the original admin can no longer administer it.
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, admin));
        config.sweep(admin);
    }
}
