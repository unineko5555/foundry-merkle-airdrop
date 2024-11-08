// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { MerkleAirdrop }from "../src/MerkleAirdrop.sol";
import { BagelToken } from "../src/BagelToken.sol";
import { Script } from "forge-std/Script.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ZkSyncChainChecker } from "foundry-devops/src/ZkSyncChainChecker.sol";

contract DeployMerkleAirdrop is Script {

    bytes32 private s_merkleRoot = 0xaa5d581231e596618465a56aa0f5870ba6e20785fe436d5bfb82b08662ccc7c4;
    uint256 private s_amountToTransfer = 4 * 25 * 1e18;

    function deployMerkleAirdrop() public returns (MerkleAirdrop, BagelToken) {
        vm.startBroadcast();
        BagelToken token = new BagelToken();
        MerkleAirdrop airdrop = new MerkleAirdrop(s_merkleRoot, IERC20(token));
        token.mint(token.owner(), s_amountToTransfer); // amount for four claimers
        IERC20(token).transfer(address(airdrop), s_amountToTransfer); // transfer tokens to the airdrop contract
        vm.stopBroadcast();
        return (airdrop, token);
    }

    function run() external returns (MerkleAirdrop, BagelToken ) {
        return deployMerkleAirdrop();
    }
}