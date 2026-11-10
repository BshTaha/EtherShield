// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {RoleBasedConfig} from "../../src/fixed/RoleBasedConfig.sol";
import {RoleBasedConfigAttacker} from "../../src/attackers/RoleBasedConfigAttacker.sol";

/// @notice The handler the fuzzer drives: hostile callers trying to seize the
///         config from every angle, mixed with the legitimate two-step handover
///         so the invariant is not trivially true by nothing ever changing.
/// @dev `expectedOwner` moves ONLY along the honest path. Every hostile action
///      is wrapped in try/catch and leaves the ghost alone, so a successful
///      hijack would put the contract and the ghost out of step.
contract ConfigHandler is Test {
    RoleBasedConfig public config;
    RoleBasedConfigAttacker public attacker;

    address[3] public actors;
    address public sink;

    /// @notice Who the two-step flow has legitimately handed the config to.
    address public expectedOwner;
    /// @notice ETH the treasury should hold.
    uint256 public ghostTreasury;

    constructor(RoleBasedConfig _config, address _admin, uint256 _funded) {
        config = _config;
        attacker = new RoleBasedConfigAttacker(_config);
        expectedOwner = _admin;
        ghostTreasury = _funded;
        sink = makeAddr("sink");
        for (uint256 i = 0; i < actors.length; i++) {
            actors[i] = makeAddr(string.concat("actor", vm.toString(i)));
        }
    }

    function fund(uint96 amount) external {
        uint256 value = bound(uint256(amount), 1, 10 ether);
        vm.deal(address(this), address(this).balance + value);
        config.deposit{value: value}();
        ghostTreasury += value;
    }

    /// @dev Hostile senders exclude address(0) deliberately, and it is worth
    ///      knowing why. OZ `Ownable2Step.acceptOwnership()` checks
    ///      `pendingOwner() == msg.sender`, and `pendingOwner()` is address(0)
    ///      until someone is nominated - so a call pranked FROM address(0)
    ///      satisfies the check and takes ownership, leaving the config
    ///      ownerless. That is unreachable on any real chain: no transaction can
    ///      originate from address(0), which has no key. It is reachable only
    ///      through `vm.prank`, so including it here would report a cheatcode
    ///      artefact as a broken invariant. See the companion regression test
    ///      test_zeroAddressAcceptanceIsAnArtefactNotAFinding in
    ///      test/RoleBasedConfig.t.sol, which pins the behaviour on purpose.
    function _isHostile(address who) internal view returns (bool) {
        return who != address(0) && who != expectedOwner;
    }

    function strangerSeizes(address who) external {
        if (!_isHostile(who)) return;
        vm.prank(who);
        try config.transferOwnership(who) {} catch {}
    }

    function strangerAccepts(address who) external {
        if (!_isHostile(who)) return;
        vm.prank(who);
        try config.acceptOwnership() {} catch {}
    }

    function strangerSweeps(address who) external {
        if (!_isHostile(who)) return;
        vm.prank(who);
        try config.sweep(who) {} catch {}
    }

    function attackerRuns() external {
        try attacker.attack() {} catch {}
    }

    function attackerClaimsOwnership() external {
        try attacker.claimOwnership() {} catch {}
    }

    /// @notice The honest handover, nominate then accept. The only path that is
    ///         allowed to move ownership, and the only one that moves the ghost.
    function honestHandover(uint8 actorSeed) external {
        address nominee = actors[bound(uint256(actorSeed), 0, actors.length - 1)];
        if (nominee == expectedOwner) return;

        vm.prank(expectedOwner);
        config.transferOwnership(nominee);
        vm.prank(nominee);
        config.acceptOwnership();
        expectedOwner = nominee;
    }

    function ownerSweeps() external {
        vm.prank(expectedOwner);
        try config.sweep(sink) {
            ghostTreasury = 0;
        } catch {}
    }

    receive() external payable {}
}

/// @title ConfigOwnershipInvariantTest
/// @notice The invariant vuln 2 is really about: ownership of the config may
///         only move along the path the contract sanctions. UnprotectedConfig
///         loses it to a single unguarded call; RoleBasedConfig must hold it
///         against any sequence of hostile calls from any address.
contract ConfigOwnershipInvariantTest is Test {
    RoleBasedConfig internal config;
    ConfigHandler internal handler;

    address internal admin = makeAddr("admin");
    address internal feeRecipient = makeAddr("feeRecipient");
    uint256 internal constant FUNDED = 10 ether;

    function setUp() public {
        vm.prank(admin);
        config = new RoleBasedConfig(feeRecipient, 100);

        vm.deal(admin, FUNDED);
        vm.prank(admin);
        config.deposit{value: FUNDED}();

        handler = new ConfigHandler(config, admin, FUNDED);

        // The handler drives the honest handover, so it has to be able to act
        // as the owner. Ownership starts with admin and is handed over on the
        // first honestHandover call; until then only admin-pranked calls work,
        // which the handler does with vm.prank.
        targetContract(address(handler));
    }

    /// @notice Ownership is always exactly where the two-step flow put it.
    function invariant_ownershipOnlyMovesThroughTheHonestPath() public view {
        assertEq(config.owner(), handler.expectedOwner(), "owner must match the legitimately handed-over owner");
    }

    /// @notice The treasury only ever leaves through an owner's sweep, and the
    ///         exploit contract never holds a wei of it.
    function invariant_treasuryOnlyLeavesByOwnerSweep() public view {
        assertEq(config.totalAssets(), handler.ghostTreasury(), "treasury must match the ghost");
        assertEq(handler.attacker().loot(), 0, "exploit contract holds nothing");
    }
}
