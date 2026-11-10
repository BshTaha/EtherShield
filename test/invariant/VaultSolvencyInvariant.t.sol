// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SecureVault} from "../../src/fixed/SecureVault.sol";
import {SecureVaultAttacker} from "../../src/attackers/SecureVaultAttacker.sol";

/// @notice The handler the fuzzer drives: three honest depositors and a
///         re-entrancy attacker, called in random order with random amounts.
/// @dev `ghostCredits` is the bookkeeping the vault is supposed to agree with.
///      Honest actions update it; the attack deliberately does not, so if the
///      drain ever worked the vault's balance and the ghost would disagree and
///      the invariant would fail. That is the detector, not a missing update.
contract VaultHandler is Test {
    SecureVault public vault;
    SecureVaultAttacker public attacker;

    address[3] public actors;

    /// @notice Sum of the credits the vault legitimately owes.
    uint256 public ghostCredits;
    /// @notice How many times the fuzzer tried the re-entrancy attack.
    uint256 public attackAttempts;
    /// @notice Total ETH the attacker has staked on attempts that went through.
    /// @dev Note an attack CAN complete without reverting - against an empty
    ///      vault the attacker just deposits and withdraws its own stake, and
    ///      the vault serving that honestly is correct behaviour, not a drain.
    ///      So "did it revert" is the wrong question. The property that matters
    ///      is whether the attacker ever ends up holding more than it put in.
    uint256 public attackerStaked;

    constructor(SecureVault _vault) {
        vault = _vault;
        attacker = new SecureVaultAttacker(_vault);
        for (uint256 i = 0; i < actors.length; i++) {
            actors[i] = makeAddr(string.concat("actor", vm.toString(i)));
        }
    }

    function deposit(uint8 actorSeed, uint96 amount) external {
        address actor = actors[bound(uint256(actorSeed), 0, actors.length - 1)];
        uint256 value = bound(uint256(amount), 1, 10 ether);

        vm.deal(actor, value);
        vm.prank(actor);
        vault.deposit{value: value}();
        ghostCredits += value;
    }

    function withdraw(uint8 actorSeed) external {
        address actor = actors[bound(uint256(actorSeed), 0, actors.length - 1)];
        uint256 credit = vault.balanceOf(actor);
        if (credit == 0) return;

        vm.prank(actor);
        vault.withdraw();
        ghostCredits -= credit;
    }

    function attack(uint96 stake) external {
        uint256 unit = bound(uint256(stake), 0.1 ether, 1 ether);
        vm.deal(address(this), address(this).balance + unit);

        attackAttempts++;
        try attacker.attack{value: unit}() {
            // Only count the stake when the call went through: a reverted
            // attack returns its ETH to this handler.
            attackerStaked += unit;
        } catch {}
    }

    receive() external payable {}
}

/// @title VaultSolvencyInvariantTest
/// @notice The invariant vuln 1 is really about: a vault must always hold
///         exactly what it owes. VulnerableVault loses this property the moment
///         the re-entrancy runs - the exploit tests show it dropping to a
///         remainder while the credits still claim 3 ETH. SecureVault must keep
///         it under any sequence of deposits, withdrawals and attacks.
/// @dev NEGATIVE CONTROL, measured 2026-11-10: a passing invariant is worthless
///      if it cannot fail, so this exact handler was re-pointed at
///      VulnerableVault outside the repo. Both invariants broke after 76 calls
///      - one deposit and one attack - with the vault holding 0.78 ETH against
///      3.48 ETH of credits, and the attacker holding 4.52 ETH on a 1.82 ETH
///      stake. The negative control is deliberately NOT a file in test/: it
///      fails by design and would turn CI red.
contract VaultSolvencyInvariantTest is Test {
    SecureVault internal vault;
    VaultHandler internal handler;

    function setUp() public {
        vault = new SecureVault();
        handler = new VaultHandler(vault);
        targetContract(address(handler));
    }

    /// @notice Solvency: the ETH in the vault equals the credits it owes. Not
    ///         "at least" - exactly. A drain breaks it downward, and a crediting
    ///         bug would break it upward.
    function invariant_vaultHoldsExactlyWhatItOwes() public view {
        assertEq(vault.totalAssets(), handler.ghostCredits(), "vault balance must equal credits owed");
    }

    /// @notice The attacker never profits: whatever it holds came out of its
    ///         own pocket. Against VulnerableVault this is exactly what fails -
    ///         the exploit walks away with the honest depositors' 3 ETH on top
    ///         of its stake.
    function invariant_attackerNeverProfits() public view {
        assertLe(handler.attacker().loot(), handler.attackerStaked(), "attacker may never hold more than it staked");
    }
}
