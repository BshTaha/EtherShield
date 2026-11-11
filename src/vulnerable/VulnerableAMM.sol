// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AMMath} from "../common/AMMath.sol";

/// @title VulnerableAMM (LAB ONLY) - toy constant-product pool X/Y
/// FLAW: swaps have NO slippage protection (no minAmountOut) and NO deadline.
/// A searcher who sees a pending swap buys first (price moves), lets the victim trade at the worse price,
/// then sells back: a "sandwich". The victim has no way to say "revert if I get less than N".
contract VulnerableAMM {
    IERC20 public immutable TOKEN_X;
    IERC20 public immutable TOKEN_Y;
    uint256 public reserveX;
    uint256 public reserveY;

    constructor(IERC20 x, IERC20 y) {
        TOKEN_X = x;
        TOKEN_Y = y;
    }

    /// Toy liquidity provision (no LP shares - this is a lab).
    function addLiquidity(uint256 ax, uint256 ay) external {
        TOKEN_X.transferFrom(msg.sender, address(this), ax);
        TOKEN_Y.transferFrom(msg.sender, address(this), ay);
        reserveX += ax;
        reserveY += ay;
    }

    function quoteXForY(uint256 amountIn) external view returns (uint256) {
        return AMMath.getAmountOut(amountIn, reserveX, reserveY);
    }

    function swapXForY(uint256 amountIn) external returns (uint256 out) {
        out = AMMath.getAmountOut(amountIn, reserveX, reserveY);
        TOKEN_X.transferFrom(msg.sender, address(this), amountIn);
        reserveX += amountIn;
        reserveY -= out;
        TOKEN_Y.transfer(msg.sender, out);
    }

    function swapYForX(uint256 amountIn) external returns (uint256 out) {
        out = AMMath.getAmountOut(amountIn, reserveY, reserveX);
        TOKEN_Y.transferFrom(msg.sender, address(this), amountIn);
        reserveY += amountIn;
        reserveX -= out;
        TOKEN_X.transfer(msg.sender, out);
    }
}
