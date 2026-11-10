// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title VulnerableSigVault  (LAB ONLY - intentionally insecure)
/// @notice A vault that pays out when `signer` signed (to, amount).
/// FLAWS (each one is exploited in test/SignatureReplay.t.sol):
///  1. No nonce            -> the same signature can be replayed unlimited times.
///  2. No chainId/contract -> the signature is valid on any chain / any copy of this vault.
///  3. No deadline         -> a signature never expires.
///  4. Raw ecrecover       -> malleable signatures (s, v) <-> (n-s, v^1) and
///                            ecrecover returns address(0) on garbage input,
///                            so if `signer == address(0)` anybody can withdraw.
contract VulnerableSigVault {
    address public signer;

    constructor(address _signer) payable {
        signer = _signer;
    }

    function withdraw(address payable to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        // The signed message only binds (to, amount): nothing makes it unique.
        bytes32 h = keccak256(abi.encodePacked(to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}
