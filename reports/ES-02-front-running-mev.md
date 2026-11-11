# ES-02 - Front-running and MEV (stolen bounty, sandwich attack)

## ES-02a - Stolen bounty (`VulnerableBounty`)
| Field | Value |
|---|---|
| Severity | **High** (full loss of the prize for the honest solver; likelihood: any mempool bot) |
| Root cause | `claim(answer)` publishes the secret answer in clear text in the public mempool; the first mined transaction wins, and ordering is decided by gas price. |
| Impact | Attacker copies the calldata, pays more gas, is mined first and takes 5 ETH. The victim's tx reverts (`already claimed`) and she only pays gas. |
| Proof (Forge) | `test_exploit_bountyStolenByFrontRunner` |
| Proof (live, Anvil) | `demo/anvil_frontrun_demo.sh` - observed result: attacker (50 gwei) = block position 0 `SUCCESS`; victim (2 gwei) = position 1 `REVERTED`; attacker +~5 ETH. |

**Fix (`SafeBounty`)** - commit/reveal with *earliest commit wins*:
1. `commit(keccak256(abi.encode(msg.sender, answer, salt)))` - the answer is hidden and bound to the sender.
2. `reveal()` must be in a **later block** than the commit.
3. First correct reveal opens a 5-block window; `finalize()` pays the correct revealer with the **earliest commit block**.

| Attack | Test | Result |
|---|---|---|
| copy the victim's reveal calldata | `test_fixed_copyingRevealCalldataIsUseless` | revert `no commit` |
| commit + reveal in the same block | `test_fixed_cannotCommitAndRevealInSameBlock` | revert `too early` |
| learn the answer from the mempool, commit late, reveal first | `test_fixed_lateCommitterLosesEvenIfHeRevealsFirst` | honest user (earlier commit) wins 5 ETH |

*Design note:* a plain commit/reveal is **not enough**. If the attacker can commit after seeing the victim's reveal and the victim's reveal is delayed one block, he could reveal first. The "earliest commit wins" rule closes that hole.

**Residual limits:** (i) guessable answers: whoever commits first with a brute-forced guess wins; (ii) a validator/builder that censors the victim's reveal for longer than the window; (iii) two extra transactions = more gas and latency.

## ES-02b - Sandwich attack on `VulnerableAMM`
| Field | Value |
|---|---|
| Severity | **High** (direct, repeatable value extraction from every swap without protection; bounded by pool depth and victim size) |
| Root cause | `swap(amountIn)` has **no `minAmountOut`** and **no `deadline`**: the user cannot express "revert if the price is worse than X". |
| Setup | Pool 1000 X / 1000 Y, 0.3% fee. Victim swaps 100 X. Attacker front-runs with 200 X. |
| Measured impact | Victim expected **90.66 Y**, received **63.96 Y** (loss **26.70 Y**, 29%). Attacker started with 200 X and ended with 230.32 X: profit **30.32 X**. |
| Proof | `test_exploit_sandwichAttack` (`forge test -vv` prints the numbers) |

Attack order inside one block: `[attacker buys Y]` -> `[victim swaps]` -> `[attacker sells Y]`.

**Fix (`SafeAMM`):** `swapXForY(amountIn, minAmountOut, deadline)` reverts with `slippage` or `expired`. Hardening added after Slither review: `SafeERC20`, `nonReentrant`, effects before interactions.

| Test | Result |
|---|---|
| `test_fixed_slippageProtectionStopsSandwich` (1% tolerance) | victim's tx reverts, funds untouched |
| `test_fixed_deadlineStopsStaleTransaction` | tx held 1 h by a builder reverts `expired` |
| `testFuzz_fixed_victimNeverBelowMinOut` (512 runs, random attacker size) | victim either gets >= minOut or reverts with nothing lost |
| `test_residual_looseSlippageStillExtractable` (40% tolerance) | **sandwich still profitable** - see below |

**Residual limits (be explicit in the defense):** slippage protection **caps** the loss, it does not remove MEV. With a loose tolerance the attacker still profits up to that tolerance. Real mitigations outside the contract: tight slippage, private order flow (Flashbots Protect / private RPC), batch auctions or intent-based DEXs (CoW-style), TWAP orders. Also note Anvil/Forge reproduce *ordering*, not a real competitive mempool.
