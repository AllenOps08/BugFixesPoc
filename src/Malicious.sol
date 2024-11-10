//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract MaliciousContract {
    function initialize() external view {
        address payable receiver = payable(msg.sender);

        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0xFF00000000000000000000000000000000000000000000000000000000000000)
            mstore(add(ptr, 0x01), receiver)
            let success := staticcall(gas(), 0x04, ptr, 0x21, ptr, 0x20)
        }
    }
}
