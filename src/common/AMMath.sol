// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Constant-product maths (x*y=k) with a 0.3% fee, same formula as Uniswap V2.
library AMMath {
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
        require(amountIn > 0 && reserveIn > 0 && reserveOut > 0, "bad input");
        uint256 inWithFee = amountIn * 997;
        return (inWithFee * reserveOut) / (reserveIn * 1000 + inWithFee);
    }
}
