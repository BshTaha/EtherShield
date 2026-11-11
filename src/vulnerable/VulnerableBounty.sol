// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title VulnerableBounty (LAB ONLY)
/// @notice Whoever submits the right answer first takes the whole prize.
/// FLAW: `claim(answer)` puts the answer in clear text in the PUBLIC mempool. A bot copies the
/// calldata and resubmits it with a higher gas price -> the bot is mined first and steals the prize.
contract VulnerableBounty {
    bytes32 public immutable ANSWER_HASH;
    bool public claimed;

    constructor(bytes32 h) payable {
        ANSWER_HASH = h;
    }

    function claim(string calldata answer) external {
        require(!claimed, "already claimed");
        require(keccak256(bytes(answer)) == ANSWER_HASH, "wrong");
        claimed = true;
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok, "send failed");
    }
}
