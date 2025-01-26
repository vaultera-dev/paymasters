// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

// solhint-disable-next-line
import {PackedUserOperation, UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

/**
 * the interface exposed by a paymaster contract, who agrees to pay the gas for user's operations.
 * a paymaster must hold a stake to cover the required entrypoint stake and also the gas for the transaction.
 */
interface IPaymaster {
    enum PostOpMode {
        opSucceeded, // user op succeeded
        opReverted, // user op reverted. still has to pay for gas.
        postOpReverted //user op succeeded, but caused postOp to revert. Now it's a 2nd call, after user's op was deliberately reverted.
    }

    /**
     * @notice This event is emitted when the paymaster allower wallet address is updated.
     */
    event VerifyingSignerUpdated(address _verifyingSigner);

    event WithdrawnPaymaster(address withdrawAddress, uint256 amount);

    /**
     * @notice Error thrown when an operation encounters a zero address.
     */
    error ZeroAddress(address _address);

    /**
     * @notice Error thrown when an operation encounters an invalid signature.
     */
    error InvalidSignature(bytes32 _signature);

    /**
     * @notice Error thrown when an operation encounters an invalid contract address.
     */
    error InvalidContractAddress(address _address);
    error NotAuthorized(address caller);
    error NotToBeCalled();

    /**
     * payment validation: check if paymaster agrees to pay.
     * Must verify sender is the entryPoint.
     * Revert to reject this request.
     * Note that bundlers will reject this method if it changes the state, unless the paymaster is trusted (whitelisted)
     * The paymaster pre-pays using its deposit, and receive back a refund after the postOp method returns.
     * @param userOp the user operation
     * @param userOpHash hash of the user's request data.
     * @param maxCost the maximum cost of this transaction (based on maximum gas and gas price from userOp)
     * @return context value to send to a postOp
     *      zero length to signify postOp is not required.
     * @return validationData signature and time-range of this operation, encoded the same as the return value of validateUserOperation
     *      <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *         otherwise, an address of an "authorizer" contract.
     *      <6-byte> validUntil - last timestamp this operation is valid. 0 for "indefinite"
     *      <6-byte> validAfter - first timestamp this operation is valid
     *      Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    /**
     * post-operation handler.
     * Must verify sender is the entryPoint
     * @param mode enum with the following options:
     *      opSucceeded - user operation succeeded.
     *      opReverted  - user op reverted. still has to pay for gas.
     *      postOpReverted - user op succeeded, but caused postOp (in mode=opSucceeded) to revert.
     *                       Now this is the 2nd call, after user's op was deliberately reverted.
     * @param context - the context value returned by validatePaymasterUserOp
     * @param actualGasCost - actual gas used so far (without this postOp call).
     */
    // function postOp(
    //     PostOpMode mode,
    //     bytes calldata context,
    //     uint256 actualGasCost
    // ) external;

    /**
     * @dev Sets the verifyingSigner. Can only be called by authorized scripts.
     * @param _verifyingSigner The new verifyingSigner.
     */
    function setVerifyingSignerAddress(address _verifyingSigner) external;

    /**
     * @dev Withdraw paymaster balance from entry point.
     * @param _withdrawAddress balance transfer to this address.
     */
    function withdrawPaymasterBalance(
        address payable _withdrawAddress
    ) external;
}
