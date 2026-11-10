// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title SafeSigVault - fixed version of VulnerableSigVault
/// @dev Fixes, one per flaw:
///  1. per-recipient `nonces`            -> a signature is single use
///  2. EIP-712 domain separator          -> binds chainId + verifyingContract (+ name/version)
///  3. `deadline` in the signed struct   -> signatures expire
///  4. OZ ECDSA.recover                  -> rejects malleable (high-s) and invalid signatures
///     + constructor refuses address(0) as signer
///  Checks-Effects-Interactions: the nonce is consumed BEFORE the ETH transfer.
contract SafeSigVault is EIP712 {
    bytes32 public constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address to,uint256 amount,uint256 nonce,uint256 deadline)");

    address public immutable signer;
    mapping(address => uint256) public nonces;

    constructor(address _signer) payable EIP712("SafeSigVault", "1") {
        require(_signer != address(0), "zero signer");
        signer = _signer;
    }

    /// @notice The digest the signer must sign (also useful for off-chain clients and tests).
    function hashWithdraw(address to, uint256 amount, uint256 nonce, uint256 deadline) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(WITHDRAW_TYPEHASH, to, amount, nonce, deadline)));
    }

    function withdraw(address payable to, uint256 amount, uint256 deadline, bytes calldata sig) external {
        require(block.timestamp <= deadline, "expired");
        // `nonces[to]++` reads the current nonce AND consumes it (effect before interaction).
        bytes32 digest = hashWithdraw(to, amount, nonces[to]++, deadline);
        require(ECDSA.recover(digest, sig) == signer, "bad sig");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}
