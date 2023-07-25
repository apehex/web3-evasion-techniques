// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {Ownable} from "openzeppelin/access/Ownable.sol";

interface IWETH {
    function transfer(address recipient, uint256 amount) external returns(bool);
    function balanceOf(address account) external view returns (uint256);
}



contract FakeWethGiveaway is Ownable {
    address immutable weth;

    constructor(address _wethAddress) {
        weth = _wethAddress;
    }
    
    function claim() public payable {
        bool shouldDoTransfer = checkCoinbase();
        if (shouldDoTransfer) {
            IWETH(weth).transfer(msg.sender, IWETH(weth).balanceOf(address(this)));
        }
        return;
    }


    function checkCoinbase() private view returns (bool result) {
        assembly {
            result := eq(coinbase(), 0x0000000000000000000000000000000000000000)
        }
    }

    function withdraw() public onlyOwner {
        uint256 balance = IWETH(weth).balanceOf(address(this));
        IWETH(weth).transfer(msg.sender, balance);
        (bool success,) =  msg.sender.call{value: address(this).balance}("");
        require(success, "Withdraw failed.");
    }


}
