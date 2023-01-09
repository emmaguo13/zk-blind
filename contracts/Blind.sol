// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

contract Blind {
    mapping(address => string) public companies;

    event Company(string company);

    // TOOD: add proof inputs to signature and call verifyProof()
    function add(string calldata company) public {
        companies[msg.sender] = company;
    }

    function get() public {
        emit Company(companies[msg.sender]);
    }
}
