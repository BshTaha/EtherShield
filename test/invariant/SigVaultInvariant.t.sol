// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeSigVault} from "../../src/fixed/SafeSigVault.sol";

/// The handler is the "attacker + honest signer" the fuzzer drives with random call sequences.
contract SigHandler is Test {
    SafeSigVault public vault;
    uint256 internal signerPk;
    address public recipient = address(0xB0B);
    uint256 public totalSigned; // sum of amounts the signer REALLY authorised

    uint256 internal lastAmount;
    uint256 internal lastDeadline;
    bytes internal lastSig;

    constructor(SafeSigVault _vault, uint256 _pk) {
        vault = _vault;
        signerPk = _pk;
    }

    function _sign(uint256 amount, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, vault.hashWithdraw(recipient, amount, nonce, deadline));
        return abi.encodePacked(r, s, v);
    }

    /// Honest flow: signer authorises `amount`, it is redeemed once.
    function authorizeAndWithdraw(uint96 amount) external {
        amount = uint96(bound(amount, 1, 1 ether));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(amount, vault.nonces(recipient), deadline);
        totalSigned += amount;
        vault.withdraw(payable(recipient), amount, deadline, sig);
        (lastAmount, lastDeadline, lastSig) = (amount, deadline, sig);
    }

    /// Attack 1: replay the last signature as-is.
    function replayLast() external {
        if (lastSig.length == 0) return;
        try vault.withdraw(payable(recipient), lastAmount, lastDeadline, lastSig) {} catch {}
    }

    /// Attack 2: reuse the last signature with a different (bigger) amount.
    function tamperAmount(uint96 newAmount) external {
        if (lastSig.length == 0) return;
        try vault.withdraw(payable(recipient), bound(newAmount, 1, 100 ether), lastDeadline, lastSig) {} catch {}
    }
}

contract SigVaultInvariantTest is Test {
    SafeSigVault vault;
    SigHandler handler;

    function setUp() public {
        (address signer, uint256 pk) = makeAddrAndKey("signer");
        vault = new SafeSigVault{value: 1000 ether}(signer);
        handler = new SigHandler(vault, pk);
        targetContract(address(handler));
    }

    /// No matter what sequence of calls: ETH paid out == ETH the signer actually authorised.
    function invariant_paidOutNeverExceedsSigned() public view {
        assertEq(handler.recipient().balance, handler.totalSigned());
        assertEq(address(vault).balance + handler.totalSigned(), 1000 ether);
    }
}
