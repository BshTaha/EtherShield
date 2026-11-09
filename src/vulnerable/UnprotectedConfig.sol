// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice INTENTIONALLY VULNERABLE - broken access control (SWC-105 / CWE-284).
///         Part of the EtherShield lab. Local chain, fake funds only.
/// @dev The contract LOOKS guarded: an `onlyOwner` modifier exists and protects
///      the fee setters, pausing, and the treasury `sweep`. The bug is the one
///      sensitive function that FORGOT the modifier - `transferOwnership`. That
///      single omission is a full compromise: anyone makes themselves owner,
///      then calls the (correctly) guarded `sweep` as the legitimate owner and
///      drains the treasury. The missing check is one line; the blast radius is
///      the whole contract. This is what a real access-control finding looks
///      like - not a contract with no guards, but a contract with one gap.

contract UnprotectedConfig {
    /// @notice The privileged administrator.
    address public owner;
    /// @notice Where protocol fees are routed.
    address public feeRecipient;
    /// @notice Fee in basis points (1% = 100).
    uint256 public feeBps;
    /// @notice When true, the protocol is halted.
    bool public paused;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event FeeRecipientUpdated(address indexed previousRecipient, address indexed newRecipient);
    event FeeBpsUpdated(uint256 previousBps, uint256 newBps);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event Deposited(address indexed from, uint256 amount);
    event Swept(address indexed to, uint256 amount);

    /// @notice Gatekeeper for privileged actions.
    /// @dev Correct and used almost everywhere - that is what makes the one
    ///      function that omits it so easy to miss in review.
    modifier onlyOwner() {
        require(msg.sender == owner, "UnprotectedConfig: not owner");
        _;
    }

    constructor(address _feeRecipient, uint256 _feeBps) {
        require(_feeRecipient != address(0), "UnprotectedConfig: zero recipient");
        require(_feeBps <= 10_000, "UnprotectedConfig: fee too high");
        owner = msg.sender;
        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Hand the admin role to `newOwner`.
    /// @dev THE BUG: this mutates `owner` with NO access control. It should be
    ///      `onlyOwner`. Because it is not, any caller can seize ownership, and
    ///      every other guard in this contract keys off `owner` - so this one
    ///      gap defeats all of them.
    function transferOwnership(address newOwner) external {
        require(newOwner != address(0), "UnprotectedConfig: zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Redirect protocol fees. Correctly guarded.
    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "UnprotectedConfig: zero recipient");
        emit FeeRecipientUpdated(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    /// @notice Update the fee. Correctly guarded.
    function setFeeBps(uint256 newBps) external onlyOwner {
        require(newBps <= 10_000, "UnprotectedConfig: fee too high");
        emit FeeBpsUpdated(feeBps, newBps);
        feeBps = newBps;
    }

    /// @notice Halt the protocol. Correctly guarded.
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resume the protocol. Correctly guarded.
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Fund the treasury (stands in for accrued protocol fees).
    function deposit() external payable {
        require(msg.value > 0, "UnprotectedConfig: zero deposit");
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Send the entire treasury to `to`. Correctly guarded by onlyOwner
    ///         - which is exactly why the exploit routes through the unprotected
    ///         transferOwnership first, then calls this as the "legitimate" owner.
    function sweep(address to) external onlyOwner {
        require(to != address(0), "UnprotectedConfig: zero recipient");
        uint256 amount = address(this).balance;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "UnprotectedConfig: sweep failed");
        emit Swept(to, amount);
    }

    /// @notice Total ETH held by the treasury.
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
