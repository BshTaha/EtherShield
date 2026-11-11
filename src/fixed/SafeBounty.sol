// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title SafeBounty - commit/reveal with "earliest commit wins"
/// Flow:  1) commit(keccak256(abi.encode(msg.sender, answer, salt)))      <- answer NOT visible
///        2) wait >= 1 block
///        3) reveal(answer, salt)    -> opens a short reveal window (first correct reveal)
///        4) finalize() after the window -> prize goes to the correct revealer with the EARLIEST commit.
/// Why it works:
///  - The commitment contains msg.sender: copying someone's reveal calldata is useless (no commit -> revert).
///  - An attacker who sees the answer in the mempool can only commit AFTER the honest user committed,
///    so his commit block is later and he loses the "earliest commit" comparison, even if his reveal lands first.
/// Residual limits: a bounty whose answer can be brute-forced/guessed can still be won by an attacker who
/// commits first; a validator that censors the honest user's reveal beyond the window can still win.
contract SafeBounty {
    uint256 public constant REVEAL_WINDOW = 5; // blocks

    bytes32 public immutable ANSWER_HASH;
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitBlock;

    address public bestClaimer;
    uint256 public bestCommitBlock;
    uint256 public windowEnd; // 0 = no correct reveal yet
    bool public paid;

    constructor(bytes32 h) payable {
        ANSWER_HASH = h;
    }

    function commit(bytes32 commitment) external {
        require(windowEnd == 0 || block.number <= windowEnd, "window closed");
        require(commitments[msg.sender] == bytes32(0), "already committed");
        commitments[msg.sender] = commitment;
        commitBlock[msg.sender] = block.number;
    }

    function reveal(string calldata answer, bytes32 salt) external {
        bytes32 c = commitments[msg.sender];
        require(c != bytes32(0), "no commit");
        require(block.number > commitBlock[msg.sender], "too early"); // forbids commit+reveal in one block
        require(c == keccak256(abi.encode(msg.sender, answer, salt)), "bad reveal");
        require(keccak256(bytes(answer)) == ANSWER_HASH, "wrong answer");
        require(windowEnd == 0 || block.number <= windowEnd, "window closed");

        if (windowEnd == 0) windowEnd = block.number + REVEAL_WINDOW;
        if (bestClaimer == address(0) || commitBlock[msg.sender] < bestCommitBlock) {
            bestClaimer = msg.sender;
            bestCommitBlock = commitBlock[msg.sender];
        }
    }

    function finalize() external {
        require(windowEnd != 0 && block.number > windowEnd, "window open");
        require(!paid, "paid");
        paid = true;
        (bool ok,) = bestClaimer.call{value: address(this).balance}("");
        require(ok, "send failed");
    }
}
