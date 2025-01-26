// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IAccessRestriction} from "../../../access/AccessRestriction.sol";
import {IPaymaster, UserOperationLib, PackedUserOperation} from "./IPaymaster01.sol";
import {IPrimeEntryPoint} from "./../../entryPoint/IPrimeEntryPoint.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import "hardhat/console.sol";

/**
 * @title Paymaster01
 * @dev Implementation of the IPaymaster01 interface with additional functionality.
 */
contract Paymaster01 is IPaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for PackedUserOperation;

    /// State variables
    address public verifyingSigner;
    IAccessRestriction public accessRestriction;
    IPrimeEntryPoint public immutable entryPoint;

    uint256 internal constant PAYMASTER_VALIDATION_GAS_OFFSET =
        UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET;
    uint256 internal constant PAYMASTER_DATA_OFFSET =
        UserOperationLib.PAYMASTER_DATA_OFFSET;
    uint256 private constant VALID_TIMESTAMP_OFFSET = PAYMASTER_DATA_OFFSET;
    uint256 private constant SIGNATURE_OFFSET = VALID_TIMESTAMP_OFFSET + 64;

    /**
     * @dev Modifier: Only accessible by authorized scripts
     */
    modifier onlyScript() {
        accessRestriction.ifScript(msg.sender);
        _;
    }

    receive() external payable {}

    /**
     * @dev Modifier: Ensures the provided address is valid (not equal to address(0)).
     * @param _address The address to check for validity.
     */
    modifier validAddress(address _address) {
        if (_address == address(0)) {
            revert ZeroAddress(address(0));
        }
        _;
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) {
            revert NotAuthorized(msg.sender);
        }
        _;
    }

    /**
     * @dev Constructor initializes the Paymaster01 contract.
     * @param _verifyingSigner The initial verifyingSigner.
     * @param _accessRestriction Address of the AccessRestriction contract.
     */
    constructor(
        address _verifyingSigner,
        address _accessRestriction,
        address _entryPoint
    ) {
        if (
            _verifyingSigner == address(0) ||
            _accessRestriction == address(0) ||
            _entryPoint == address(0)
        ) {
            revert ZeroAddress(address(0));
        }
        verifyingSigner = _verifyingSigner;
        accessRestriction = IAccessRestriction(_accessRestriction);
        entryPoint = IPrimeEntryPoint(_entryPoint);
    }

    /// @inheritdoc IPaymaster
    function setVerifyingSignerAddress(
        address _verifyingSigner
    ) external override onlyScript validAddress(_verifyingSigner) {
        verifyingSigner = _verifyingSigner;
        emit VerifyingSignerUpdated(_verifyingSigner);
    }

    /// @inheritdoc IPaymaster
    function withdrawPaymasterBalance(
        address payable _withdrawAddress
    ) external override onlyScript validAddress(_withdrawAddress) {
        uint256 withdrawAmount = entryPoint.balanceOf(address(this));
        emit WithdrawnPaymaster(_withdrawAddress, withdrawAmount);
        entryPoint.withdrawTo(_withdrawAddress, withdrawAmount);
    }

    function getHash(
        PackedUserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter
    ) public view returns (bytes32) {
        //can't use userOp.hash(), since it contains also the paymasterAndData itself.
        address sender = userOp.getSender();
        return
            keccak256(
                abi.encode(
                    sender,
                    userOp.nonce,
                    keccak256(userOp.initCode),
                    keccak256(userOp.callData),
                    userOp.accountGasLimits,
                    userOp.preVerificationGas,
                    userOp.gasFees,
                    block.chainid,
                    address(this),
                    validUntil,
                    validAfter
                )
            );
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /**userOpHash */,
        uint256 /**maxCost*/
    )
        external
        view
        override
        returns (bytes memory context, uint256 validationData)
    {
        (
            uint48 validUntil,
            uint48 validAfter,
            bytes calldata signature
        ) = parsePaymasterAndData(userOp.paymasterAndData);

        if (signature.length != 64 && signature.length != 65) {
            revert InvalidSignature(bytes32(signature));
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(
            getHash(userOp, validUntil, validAfter)
        );

        if (verifyingSigner != ECDSA.recover(hash, signature)) {
            // will revert

            return ("", _packValidationData(true, validUntil, validAfter));
        }
        return ("", _packValidationData(false, validUntil, validAfter));
    }

    // /// @inheritdoc IPaymaster
    // function postOp(
    //     PostOpMode mode,
    //     bytes calldata context,
    //     uint256 actualGasCost
    // ) external pure override {
    //     (mode, context, actualGasCost);
    //     revert NotToBeCalled();
    // }

    /**
     * @dev Internal function to parse paymaster and data from user operation.
     *
     * This function decodes the paymaster's data, extracting the `validUntil` and `validAfter` timestamps
     * along with the associated signature from the provided `paymasterAndData` byte array.
     * The `validUntil` and `validAfter` are extracted as `uint48` values, which represent the validity
     * period of the operation, and the signature is extracted as a `bytes` array, which can be used for
     * verification or authorization purposes.
     *
     * @param paymasterAndData The user operation data containing the paymaster's metadata and signature.
     *
     * @return validUntil The timestamp until which the operation is valid.
     * @return validAfter The timestamp from which the operation is valid.
     * @return signature The paymaster's signature for the operation.
     */
    function parsePaymasterAndData(
        bytes calldata paymasterAndData
    )
        public
        pure
        returns (uint48 validUntil, uint48 validAfter, bytes calldata signature)
    {
        (validUntil, validAfter) = abi.decode(
            paymasterAndData[VALID_TIMESTAMP_OFFSET:],
            (uint48, uint48)
        );
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }
}
