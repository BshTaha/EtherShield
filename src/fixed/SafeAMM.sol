// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AMMath} from "../common/AMMath.sol";

/// @title SafeAMM - same pool + slippage bound + deadline (+ hardening found by Slither)
/// swap(amountIn, minAmountOut, deadline): the transaction REVERTS if the price moved against the user
/// beyond what they accept, or if it stays pending too long (stale-transaction attack).
/// Hardening added after the Slither review (see reports/ES-04-slither-triage.md):
///   - SafeERC20      : checks the return value of transfer/transferFrom (slither: unchecked-transfer)
///   - nonReentrant   : defence in depth against tokens with callbacks (ERC777-style)
///   - effects first  : reserves are updated BEFORE the token transfers (Checks-Effects-Interactions)
/// Residual limit: slippage protection CAPS the loss, it does not remove MEV. A victim who sets a loose
/// tolerance can still be sandwiched up to that tolerance. Real mitigations: tight slippage,
/// private order flow (e.g. Flashbots Protect), batch auctions / intent-based DEXs.
contract SafeAMM is ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable TOKEN_X;
    IERC20 public immutable TOKEN_Y;
    uint256 public reserveX;
    uint256 public reserveY;

    constructor(IERC20 x, IERC20 y) {
        TOKEN_X = x;
        TOKEN_Y = y;
    }

    function addLiquidity(uint256 ax, uint256 ay) external nonReentrant {
        reserveX += ax;
        reserveY += ay;
        TOKEN_X.safeTransferFrom(msg.sender, address(this), ax);
        TOKEN_Y.safeTransferFrom(msg.sender, address(this), ay);
    }

    function quoteXForY(uint256 amountIn) external view returns (uint256) {
        return AMMath.getAmountOut(amountIn, reserveX, reserveY);
    }

    function swapXForY(uint256 amountIn, uint256 minAmountOut, uint256 deadline)
        external
        nonReentrant
        returns (uint256 out)
    {
        require(block.timestamp <= deadline, "expired");
        out = AMMath.getAmountOut(amountIn, reserveX, reserveY);
        require(out >= minAmountOut, "slippage");
        reserveX += amountIn;
        reserveY -= out;
        TOKEN_X.safeTransferFrom(msg.sender, address(this), amountIn);
        TOKEN_Y.safeTransfer(msg.sender, out);
    }

    function swapYForX(uint256 amountIn, uint256 minAmountOut, uint256 deadline)
        external
        nonReentrant
        returns (uint256 out)
    {
        require(block.timestamp <= deadline, "expired");
        out = AMMath.getAmountOut(amountIn, reserveY, reserveX);
        require(out >= minAmountOut, "slippage");
        reserveY += amountIn;
        reserveX -= out;
        TOKEN_Y.safeTransferFrom(msg.sender, address(this), amountIn);
        TOKEN_X.safeTransfer(msg.sender, out);
    }
}
