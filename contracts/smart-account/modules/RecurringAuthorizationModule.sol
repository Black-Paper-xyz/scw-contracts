// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BaseAuthorizationModule} from "./BaseAuthorizationModule.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title Smart Contract Recurring Transaction Module for Biconomy Smart Accounts.
 * @dev Compatible with Biconomy Modular Interface v 0.1
 *
 * @author Coriolan Pinhas - <coriolan.pinhas@black-paper.xyz>
 */

contract RecurringAuthorizationModule is BaseAuthorizationModule {

    struct RecurringUserOp {
        UserOperation userOp;
        uint256 interval;
        uint256 lastUserOp;
    }

    string public constant NAME = "Smart Contract Recurring Authorization Module";
    string public constant VERSION = "0.1.0";

    mapping(bytes32 => RecurringUserOp) public authorizedRecurringUserOp;

    error ZeroIntervalNotAllowed();

    function manageRecurringUserOp(
        RecurringUserOp memory recurringUserOp
    ) external {
        if (recurringUserOp.interval == 0) revert ZeroIntervalNotAllowed();
        bytes32 operation = keccak256(abi.encode(msg.sender, recurringUserOp.userOp));
        authorizedRecurringUserOp[operation] = recurringUserOp;
    }

    function removeRecurringUserOp(
        UserOperation calldata userOp
    ) external {
        bytes32 operation = keccak256(abi.encode(msg.sender, userOp));
        RecurringUserOp storage recurringUserOp = authorizedRecurringUserOp[operation];
        delete recurringUserOp.userOp;
        delete recurringUserOp.interval;
        delete recurringUserOp.lastUserOp;
    }

    /**
     * @dev validates userOperation
     * @param userOp User Operation to be validated.
     * @return sigValidationResult 0 if signature is valid, SIG_VALIDATION_FAILED otherwise.
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32
    ) external returns (uint256) {
        bytes32 operation = keccak256(abi.encode(userOp.sender, userOp));
        RecurringUserOp storage recurringUserOp = authorizedRecurringUserOp[operation];

        if (recurringUserOp.interval == 0) {
            return SIG_VALIDATION_FAILED;
        }

        if (recurringUserOp.interval + recurringUserOp.lastUserOp <= block.timestamp) {
            recurringUserOp.lastUserOp = block.timestamp;
            return VALIDATION_SUCCESS;
        }

        return SIG_VALIDATION_FAILED;
        
    }

    /**
     * @dev isValidSignature according to BaseAuthorizationModule
     * @param _dataHash Hash of the data to be validated.
     * @param _signature Signature over the the _dataHash.
     * @return always returns 0xffffffff as signing messages is not supported by SessionKeys
     */
    function isValidSignature(
        bytes32 _dataHash,
        bytes memory _signature
    ) public pure override returns (bytes4) {
        (_dataHash, _signature);
        return 0xffffffff; // do not support it here
    }
}
