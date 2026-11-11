// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {VulnerableBounty} from "../src/vulnerable/VulnerableBounty.sol";
import {SafeBounty} from "../src/fixed/SafeBounty.sol";
import {VulnerableAMM} from "../src/vulnerable/VulnerableAMM.sol";
import {SafeAMM} from "../src/fixed/SafeAMM.sol";
import {MockToken} from "../src/mocks/MockToken.sol";

/// ES-02  Front-running / MEV.
/// In Forge we model the MEMPOOL ORDER by choosing the order of vm.prank calls inside one "block".
/// (The live gas-price race is shown on Anvil with demo/anvil_frontrun_demo.sh.)
contract FrontRunningTest is Test {
    address alice = makeAddr("alice"); // honest solver / victim
    address mallory = makeAddr("mallory"); // MEV bot / attacker
    string constant ANSWER = "ethereum";
    bytes32 constant SALT = keccak256("alice-secret-salt");

    // ================== Scenario A : stolen bounty ==================

    function test_exploit_bountyStolenByFrontRunner() public {
        VulnerableBounty b = new VulnerableBounty{value: 5 ether}(keccak256(bytes(ANSWER)));

        // Alice's tx claim("ethereum") is PENDING and visible. Mallory copies the calldata,
        // pays a higher gas price, and is ordered first.
        vm.prank(mallory);
        b.claim(ANSWER); // mined first
        vm.prank(alice);
        vm.expectRevert("already claimed");
        b.claim(ANSWER); // the honest user's tx now reverts

        assertEq(mallory.balance, 5 ether, "attacker took the prize");
        assertEq(alice.balance, 0);
    }

    function test_fixed_copyingRevealCalldataIsUseless() public {
        SafeBounty b = new SafeBounty{value: 5 ether}(keccak256(bytes(ANSWER)));
        vm.prank(alice);
        b.commit(keccak256(abi.encode(alice, ANSWER, SALT)));
        vm.roll(block.number + 1);

        // Mallory sees reveal(ANSWER, SALT) in the mempool and copies it:
        vm.prank(mallory);
        vm.expectRevert("no commit");
        b.reveal(ANSWER, SALT);
    }

    function test_fixed_lateCommitterLosesEvenIfHeRevealsFirst() public {
        SafeBounty b = new SafeBounty{value: 5 ether}(keccak256(bytes(ANSWER)));

        vm.prank(alice);
        b.commit(keccak256(abi.encode(alice, ANSWER, SALT))); // block 1
        vm.roll(block.number + 1); // block 2

        // Alice's reveal is pending. Mallory learns the answer from it and races:
        vm.prank(mallory);
        b.commit(keccak256(abi.encode(mallory, ANSWER, SALT))); // block 2 (his commit is LATER than alice's)
        vm.roll(block.number + 1); // block 3

        vm.prank(mallory);
        b.reveal(ANSWER, SALT); // Mallory's reveal is mined first...
        vm.prank(alice);
        b.reveal(ANSWER, SALT); // ...Alice's reveal comes right after

        vm.roll(block.number + b.REVEAL_WINDOW() + 1);
        b.finalize();
        assertEq(alice.balance, 5 ether, "earliest commit wins");
        assertEq(mallory.balance, 0);
    }

    function test_fixed_cannotCommitAndRevealInSameBlock() public {
        SafeBounty b = new SafeBounty{value: 5 ether}(keccak256(bytes(ANSWER)));
        vm.startPrank(mallory);
        b.commit(keccak256(abi.encode(mallory, ANSWER, SALT)));
        vm.expectRevert("too early");
        b.reveal(ANSWER, SALT);
        vm.stopPrank();
    }

    function test_fixed_wrongAnswerRejected() public {
        SafeBounty b = new SafeBounty{value: 5 ether}(keccak256(bytes(ANSWER)));
        vm.startPrank(alice);
        b.commit(keccak256(abi.encode(alice, "bitcoin", SALT)));
        vm.roll(block.number + 1);
        vm.expectRevert("wrong answer");
        b.reveal("bitcoin", SALT);
        vm.stopPrank();
    }

    // ================== Scenario B : sandwich attack ==================

    uint256 constant POOL = 1000 ether;
    uint256 constant VICTIM_IN = 100 ether;
    uint256 constant ATTACKER_IN = 200 ether;

    function _tokens() internal returns (MockToken x, MockToken y) {
        x = new MockToken("TokenX", "X");
        y = new MockToken("TokenY", "Y");
    }

    function _fund(MockToken x, MockToken y, address who, address pool, uint256 amtX, uint256 amtY) internal {
        x.mint(who, amtX);
        y.mint(who, amtY);
        vm.startPrank(who);
        x.approve(pool, type(uint256).max);
        y.approve(pool, type(uint256).max);
        vm.stopPrank();
    }

    function test_exploit_sandwichAttack() public {
        (MockToken x, MockToken y) = _tokens();
        VulnerableAMM amm = new VulnerableAMM(x, y);
        _fund(x, y, address(this), address(amm), POOL, POOL);
        amm.addLiquidity(POOL, POOL);
        _fund(x, y, alice, address(amm), VICTIM_IN, 0);
        _fund(x, y, mallory, address(amm), ATTACKER_IN, 0);

        uint256 expected = amm.quoteXForY(VICTIM_IN); // what Alice believes she will get

        // Block ordering chosen by the attacker:  [attacker buy] -> [victim swap] -> [attacker sell]
        vm.startPrank(mallory);
        uint256 yBought = amm.swapXForY(ATTACKER_IN); // 1. front-run: pushes the price up
        vm.stopPrank();
        vm.prank(alice);
        uint256 got = amm.swapXForY(VICTIM_IN); // 2. victim executes at a worse price
        vm.prank(mallory);
        uint256 xBack = amm.swapYForX(yBought); // 3. back-run: sells for a profit

        uint256 profit = xBack - ATTACKER_IN;
        console2.log("Victim expected Y :", expected);
        console2.log("Victim received Y :", got);
        console2.log("Victim loss (Y)   :", expected - got);
        console2.log("Attacker profit(X):", profit);

        assertLt(got, expected, "victim got less than quoted");
        assertGt(xBack, ATTACKER_IN, "attacker ends with more X than he started");
    }

    function test_fixed_slippageProtectionStopsSandwich() public {
        (MockToken x, MockToken y) = _tokens();
        SafeAMM amm = new SafeAMM(x, y);
        _fund(x, y, address(this), address(amm), POOL, POOL);
        amm.addLiquidity(POOL, POOL);
        _fund(x, y, alice, address(amm), VICTIM_IN, 0);
        _fund(x, y, mallory, address(amm), ATTACKER_IN, 0);

        uint256 minOut = (amm.quoteXForY(VICTIM_IN) * 99) / 100; // 1% tolerance
        uint256 deadline = block.timestamp + 5 minutes;

        vm.prank(mallory);
        amm.swapXForY(ATTACKER_IN, 0, deadline); // attacker front-runs as before

        vm.prank(alice);
        vm.expectRevert("slippage"); // victim's tx reverts instead of executing at a bad price
        amm.swapXForY(VICTIM_IN, minOut, deadline);

        assertEq(y.balanceOf(alice), 0);
        assertEq(x.balanceOf(alice), VICTIM_IN, "victim keeps her funds");
    }

    function test_fixed_deadlineStopsStaleTransaction() public {
        (MockToken x, MockToken y) = _tokens();
        SafeAMM amm = new SafeAMM(x, y);
        _fund(x, y, address(this), address(amm), POOL, POOL);
        amm.addLiquidity(POOL, POOL);
        _fund(x, y, alice, address(amm), VICTIM_IN, 0);

        uint256 deadline = block.timestamp + 5 minutes;
        vm.warp(block.timestamp + 1 hours); // tx was held back by a builder for an hour
        vm.prank(alice);
        vm.expectRevert("expired");
        amm.swapXForY(VICTIM_IN, 0, deadline);
    }

    /// HONEST LIMIT: with a loose tolerance (40%) the sandwich still works, only up to that bound.
    function test_residual_looseSlippageStillExtractable() public {
        (MockToken x, MockToken y) = _tokens();
        SafeAMM amm = new SafeAMM(x, y);
        _fund(x, y, address(this), address(amm), POOL, POOL);
        amm.addLiquidity(POOL, POOL);
        _fund(x, y, alice, address(amm), VICTIM_IN, 0);
        _fund(x, y, mallory, address(amm), ATTACKER_IN, 0);

        uint256 expected = amm.quoteXForY(VICTIM_IN);
        uint256 minOut = (expected * 60) / 100; // 40% tolerance
        uint256 deadline = block.timestamp + 5 minutes;

        vm.prank(mallory);
        uint256 yBought = amm.swapXForY(ATTACKER_IN, 0, deadline);
        vm.prank(alice);
        uint256 got = amm.swapXForY(VICTIM_IN, minOut, deadline); // passes: within her tolerance
        vm.prank(mallory);
        uint256 xBack = amm.swapYForX(yBought, 0, deadline);

        assertGe(got, minOut, "victim loss is capped by her tolerance");
        assertLt(got, expected, "but she still lost value");
        assertGt(xBack, ATTACKER_IN, "and the attacker still profits");
    }

    // ================== Fuzz ==================

    /// For ANY front-run size the attacker picks, the victim never receives less than her minOut.
    function testFuzz_fixed_victimNeverBelowMinOut(uint96 attackerIn) public {
        attackerIn = uint96(bound(attackerIn, 1 ether, 500 ether));
        (MockToken x, MockToken y) = _tokens();
        SafeAMM amm = new SafeAMM(x, y);
        _fund(x, y, address(this), address(amm), POOL, POOL);
        amm.addLiquidity(POOL, POOL);
        _fund(x, y, alice, address(amm), VICTIM_IN, 0);
        _fund(x, y, mallory, address(amm), attackerIn, 0);

        uint256 minOut = (amm.quoteXForY(VICTIM_IN) * 98) / 100;
        uint256 deadline = block.timestamp + 5 minutes;
        vm.prank(mallory);
        amm.swapXForY(attackerIn, 0, deadline);

        vm.prank(alice);
        try amm.swapXForY(VICTIM_IN, minOut, deadline) returns (uint256 out) {
            assertGe(out, minOut);
        } catch {
            assertEq(y.balanceOf(alice), 0); // reverted -> no funds lost
            assertEq(x.balanceOf(alice), VICTIM_IN);
        }
    }
}
