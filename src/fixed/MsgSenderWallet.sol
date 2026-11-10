// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice The FIXED counterpart to TxOriginWallet (SWC-115 / CWE-287).
///         EtherShield lab. Same ABI as the vulnerable twin, so the only
///         variable that changes between them is the question the guard asks.
/// @dev WHY THIS IS A FIX AND NOT A PATCH.
///
///      The obvious reading of the bug is "someone typed `tx.origin` where they
///      meant `msg.sender`", and the obvious repair is to swap the identifier.
///      That is necessary but it is not the lesson, because the vulnerable twin
///      proves the deeper problem: it had TWO authorization implementations. A
///      `tx.origin` modifier guarded the money, and a later author wrote
///      `msg.sender` checks inline for the recovery functions. Half the surface
///      was exploitable and half was not, and nothing in the code made that
///      visible. Swapping one identifier in one modifier would have fixed the
///      symptom while leaving the real defect - authorization decided in more
///      than one place - alive for the next function someone adds.
///
///      So this wallet applies two layers:
///
///        1. `msg.sender` is the only identity consulted. `tx.origin` tells you
///           who signed the transaction, which is NOT who is calling you, and
///           it has no legitimate use in authorization at all. Its real uses are
///           plumbing - refunds and relayer accounting - never "may you do this".
///           Asking `msg.sender` means a hostile intermediary is judged on its
///           own identity, so the confused-deputy route simply does not exist:
///           the victim's signature no longer carries authority down the stack.
///
///        2. ONE modifier, applied to every privileged function, including the
///           two the vulnerable twin checked inline. One place to read, one
///           place to audit, nothing to drift. In production you would inherit
///           OpenZeppelin `Ownable` for exactly this reason - note that its
///           `_checkOwner()` compares against `msg.sender` - and that is the
///           route RoleBasedConfig takes for vuln 2. It is hand-rolled here so
///           the diff against TxOriginWallet shows the one changed idea and
///           nothing else.
///
///      WHAT THIS FIX DELIBERATELY DOES NOT DO: the vulnerable author chose
///      `tx.origin` for a reason - it keeps working when the owner routes calls
///      through a helper contract. That convenience is lost here, and losing it
///      is correct. If it is genuinely wanted, the safe shape is an explicit
///      allowlist the owner nominates (`mapping(address => bool) delegates`,
///      checked with `msg.sender`), which grants authority to a NAMED contract
///      instead of implicitly trusting whatever happens to be in the call stack.
contract MsgSenderWallet {
    /// @notice The address that owns the funds in this wallet.
    address public owner;
    /// @notice An address allowed to take over if the owner's key is lost.
    address public recoveryAddress;

    event Deposited(address indexed from, uint256 amount);
    event Transferred(address indexed to, uint256 amount);
    event Swept(address indexed to, uint256 amount);
    event RecoveryAddressUpdated(address indexed previousRecovery, address indexed newRecovery);
    event OwnershipRecovered(address indexed previousOwner, address indexed newOwner);

    /// @notice The single gatekeeper for every privileged call.
    /// @dev THE FIX. `msg.sender` is the immediate caller. A contract calling on
    ///      the owner's behalf is itself the caller and is rejected, however the
    ///      owner was persuaded to start the transaction.
    modifier onlyOwner() {
        require(msg.sender == owner, "MsgSenderWallet: not owner");
        _;
    }

    /// @dev Used by the recovery takeover, the one privileged call whose
    ///      authority belongs to the nominee rather than the owner.
    modifier onlyRecovery() {
        require(recoveryAddress != address(0), "MsgSenderWallet: no recovery set");
        require(msg.sender == recoveryAddress, "MsgSenderWallet: not recovery");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Fund the wallet. Open to anyone - depositing is not privileged.
    function deposit() external payable {
        require(msg.value > 0, "MsgSenderWallet: zero deposit");
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Send `amount` to `to`.
    function transferTo(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "MsgSenderWallet: zero recipient");
        require(amount <= address(this).balance, "MsgSenderWallet: insufficient balance");
        emit Transferred(to, amount);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "MsgSenderWallet: transfer failed");
    }

    /// @notice Send the entire balance to `to`.
    function sweep(address to) external onlyOwner {
        require(to != address(0), "MsgSenderWallet: zero recipient");
        uint256 amount = address(this).balance;
        emit Swept(to, amount);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "MsgSenderWallet: sweep failed");
    }

    /// @notice Nominate an address that can recover the wallet.
    /// @dev Was already `msg.sender`-checked in the vulnerable twin, but inline.
    ///      It now goes through the same modifier as everything else.
    function setRecoveryAddress(address newRecovery) external onlyOwner {
        require(newRecovery != address(0), "MsgSenderWallet: zero recovery");
        emit RecoveryAddressUpdated(recoveryAddress, newRecovery);
        recoveryAddress = newRecovery;
    }

    /// @notice Take over the wallet as the nominated recovery address.
    function recoverOwnership() external onlyRecovery {
        emit OwnershipRecovered(owner, msg.sender);
        owner = msg.sender;
    }

    /// @notice ETH held by this wallet.
    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
