// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {MsgSenderWallet} from "../../src/fixed/MsgSenderWallet.sol";
import {MsgSenderWalletAttacker} from "../../src/attackers/MsgSenderWalletAttacker.sol";

/// @notice The handler the fuzzer drives: the victim repeatedly taking the
///         phishing lure - by calling it and by sending it ETH - mixed with
///         strangers trying to sweep directly and the owner spending honestly.
/// @dev Every phishing route sets the victim as BOTH msg.sender and tx.origin,
///      which is exactly the condition that drained TxOriginWallet. Only
///      `ownerPays` is allowed to move money, and only it touches the ghost.
contract WalletHandler is Test {
    MsgSenderWallet public wallet;
    MsgSenderWalletAttacker public attacker;

    address public immutable victim;
    address public sink;

    /// @notice Everything ever deposited into the wallet.
    uint256 public funded;
    /// @notice Everything the OWNER deliberately paid out.
    uint256 public paidOut;
    /// @notice How many phishing attempts the fuzzer made.
    uint256 public phishAttempts;

    constructor(MsgSenderWallet _wallet, address _victim, uint256 _funded) {
        wallet = _wallet;
        victim = _victim;
        funded = _funded;
        attacker = new MsgSenderWalletAttacker(_wallet);
        sink = makeAddr("sink");
    }

    function fund(uint96 amount) external {
        uint256 value = bound(uint256(amount), 1, 10 ether);
        vm.deal(address(this), address(this).balance + value);
        wallet.deposit{value: value}();
        funded += value;
    }

    /// @notice The victim signs a call into the hostile contract.
    function phishByCall() external {
        phishAttempts++;
        vm.prank(victim, victim);
        try attacker.claimReward() {} catch {}
    }

    /// @notice The victim merely sends ETH to the hostile contract. Note the
    ///         value comes from this handler's balance - vm.prank spoofs the
    ///         sender, it does not move anyone's ETH - which is all the attack
    ///         needs: what matters is that tx.origin is the victim.
    function phishByTransfer(uint96 tip) external {
        uint256 value = bound(uint256(tip), 1, 1 ether);
        vm.deal(address(this), address(this).balance + value);

        phishAttempts++;
        vm.prank(victim, victim);
        (bool ok,) = address(attacker).call{value: value}("");
        // A reverted send keeps the ETH here; either way the wallet is the thing
        // under test, and the invariants below cover it.
        ok;
    }

    /// @notice The victim is tricked into the recovery-door variant too.
    function phishRecoveryDoor() external {
        phishAttempts++;
        vm.prank(victim, victim);
        try attacker.claimOwnershipByRecovery() {} catch {}
    }

    function strangerSweeps(address who) external {
        if (who == wallet.owner()) return;
        vm.prank(who, who);
        try wallet.sweep(who) {} catch {}
    }

    /// @notice The owner spending their own money - the only sanctioned way for
    ///         ETH to leave, and the only action that moves the ghost.
    function ownerPays(uint96 amount) external {
        uint256 held = wallet.balance();
        if (held == 0) return;
        uint256 value = bound(uint256(amount), 1, held);

        vm.prank(victim, victim);
        wallet.transferTo(sink, value);
        paidOut += value;
    }

    receive() external payable {}
}

/// @title WalletAuthorityInvariantTest
/// @notice The invariant vuln 3 is really about: ETH leaves the wallet only
///         when the OWNER asks it to. TxOriginWallet loses this the first time
///         the owner signs anything that touches hostile code; MsgSenderWallet
///         must hold it however many times the victim takes the lure.
contract WalletAuthorityInvariantTest is Test {
    MsgSenderWallet internal wallet;
    WalletHandler internal handler;

    address internal victim = makeAddr("victim");
    uint256 internal constant FUNDED = 10 ether;

    function setUp() public {
        vm.prank(victim);
        wallet = new MsgSenderWallet();

        vm.deal(victim, FUNDED);
        vm.prank(victim);
        wallet.deposit{value: FUNDED}();

        handler = new WalletHandler(wallet, victim, FUNDED);
        targetContract(address(handler));
    }

    /// @notice Conservation of the owner's money: what is still in the wallet
    ///         plus what the owner deliberately spent is everything that was
    ///         ever put in. No phishing route adds a third destination.
    function invariant_moneyOnlyLeavesWhenTheOwnerAsks() public view {
        assertEq(
            wallet.balance() + handler.paidOut(),
            handler.funded(),
            "wallet balance plus owner spending must equal deposits"
        );
    }

    /// @notice The exploit contract never ends up holding anything - not swept
    ///         funds, and not even the tips the victim sent it, because a
    ///         reverting attack reverts the victim's whole transaction.
    function invariant_exploitHoldsNothing() public view {
        assertEq(handler.attacker().loot(), 0, "exploit contract must stay empty");
        assertFalse(handler.attacker().hijacked(), "no attack may ever report success");
    }

    /// @notice And nothing about the wallet's authority moves either.
    function invariant_authorityNeverMoves() public view {
        assertEq(wallet.owner(), victim, "owner unchanged");
        assertEq(wallet.recoveryAddress(), address(0), "no recovery nominee was ever planted");
    }
}
