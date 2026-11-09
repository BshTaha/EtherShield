// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice INTENTIONALLY VULNERABLE - tx.origin authentication (SWC-115 /
///         CWE-287). Part of the EtherShield lab. Local chain, fake funds only.
/// @dev A personal wallet whose author believed `tx.origin` and `msg.sender`
///      were interchangeable ways to ask "is this the owner?". They are not:
///
///        msg.sender = who called THIS contract (the immediate caller)
///        tx.origin  = who signed the transaction (always an EOA, never a
///                     contract, and unchanged however deep the call stack goes)
///
///      So `tx.origin == owner` does not mean "the owner is calling me". It
///      means "the owner is somewhere in the call stack" - which is also true
///      when the owner is tricked into calling a hostile contract that calls
///      this wallet on their behalf. The signature the owner provides for a
///      harmless-looking transaction becomes authority for a withdrawal they
///      never approved. This is the on-chain form of a confused-deputy /
///      phishing attack, and no amount of care by the owner fixes it: the flaw
///      is that the wallet asks the wrong question.
///
///      THE SHAPE OF THE FINDING: this wallet is not uniformly wrong. The
///      `onlyOwner` modifier (tx.origin) guards the money-moving functions,
///      while `setRecoveryAddress` was written later by someone who used
///      `msg.sender` inline. The result is a wallet where some privileged calls
///      are hijackable through a phishing contract and others are not - which
///      is exactly how this bug shows up in real code, and what makes the
///      exploit tests worth writing: they prove WHICH half is reachable.
///
///      Note `emit` sits before each external call here, so `forge lint` and
///      Slither report only the tx.origin finding rather than incidental
///      reentrancy-events noise in the vuln-3 triage.
contract TxOriginWallet {
    /// @notice The EOA that owns the funds in this wallet.
    address public owner;
    /// @notice An address allowed to take over if the owner's key is lost.
    address public recoveryAddress;

    event Deposited(address indexed from, uint256 amount);
    event Transferred(address indexed to, uint256 amount);
    event Swept(address indexed to, uint256 amount);
    event RecoveryAddressUpdated(address indexed previousRecovery, address indexed newRecovery);
    event OwnershipRecovered(address indexed previousOwner, address indexed newOwner);

    /// @notice Gatekeeper for moving funds.
    /// @dev THE BUG. `tx.origin` is the transaction signer, not the caller, so
    ///      this check passes for ANY contract calling on the owner's behalf
    ///      inside a transaction the owner signed. The author's intent was
    ///      convenience - it keeps working when the owner routes calls through
    ///      a helper contract - and that convenience is the vulnerability.
    modifier onlyOwner() {
        require(tx.origin == owner, "TxOriginWallet: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Fund the wallet. Open to anyone - depositing is not privileged.
    function deposit() external payable {
        require(msg.value > 0, "TxOriginWallet: zero deposit");
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Send `amount` to `to`.
    /// @dev Hijackable: a hostile contract calls this while the owner is the
    ///      transaction's origin, and the guard waves it through.
    function transferTo(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "TxOriginWallet: zero recipient");
        require(amount <= address(this).balance, "TxOriginWallet: insufficient balance");
        emit Transferred(to, amount);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "TxOriginWallet: transfer failed");
    }

    /// @notice Send the entire balance to `to`.
    /// @dev Hijackable for the same reason, and the one the exploit prefers:
    ///      one call, whole balance, no amount to guess.
    function sweep(address to) external onlyOwner {
        require(to != address(0), "TxOriginWallet: zero recipient");
        uint256 amount = address(this).balance;
        emit Swept(to, amount);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "TxOriginWallet: sweep failed");
    }

    /// @notice Nominate an address that can recover the wallet.
    /// @dev NOT hijackable: this one checks `msg.sender`, so a hostile
    ///      intermediary fails here even though it passed the guard above. The
    ///      contrast is the whole lesson - same transaction, same signer, two
    ///      different answers, because only one of these asks who is calling.
    function setRecoveryAddress(address newRecovery) external {
        require(msg.sender == owner, "TxOriginWallet: not owner");
        require(newRecovery != address(0), "TxOriginWallet: zero recovery");
        emit RecoveryAddressUpdated(recoveryAddress, newRecovery);
        recoveryAddress = newRecovery;
    }

    /// @notice Take over the wallet as the nominated recovery address.
    /// @dev Also correctly checks `msg.sender`.
    function recoverOwnership() external {
        require(recoveryAddress != address(0), "TxOriginWallet: no recovery set");
        require(msg.sender == recoveryAddress, "TxOriginWallet: not recovery");
        emit OwnershipRecovered(owner, msg.sender);
        owner = msg.sender;
    }

    /// @notice ETH held by this wallet.
    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
