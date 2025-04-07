// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@semaphore-protocol/contracts/Semaphore.sol";
import "./interfaces/ISemaphoreVerifier.sol";
import "@semaphore-protocol/contracts/base/SemaphoreCore.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract ElectoralBond is Semaphore, ReentrancyGuard {
    uint256 public groupId;
    mapping(uint256 => bool) public spentNullifiers;
    mapping(uint256 => uint256) public nullifierToAmount;
    mapping(uint256 => uint256) public nullifierToWithdrawn;
    
    // Track identity commitments to prevent reuse
    mapping(uint256 => bool) public usedIdentityCommitments;
    
    event BondCreated(
        uint256 amount,
    );
    
    event BondWithdrawn(
        uint256 nullifierHash,
        address recipient,
        uint256 amount
    );

    constructor(address _verifier) Semaphore(ISemaphoreVerifier(_verifier)) {
        groupId = 1;
        createGroup(groupId, 20, address(this));
    }
    
    /**
     *  Create a new electoral bond by depositing ETH and getting an identity commitment
     *   use a randomSecret A random string provided by the voter to generate the identity
     *  return the  generated identityCommitment  to the bond creater  
     *  return the  nullifierHash to the bond creater 
     */
    function createBond(
        bytes32 randomSecret
    ) external payable nonReentrant returns (uint256 identityCommitment, uint256 nullifierHash) {
        require(msg.value > 0, "ElectoralBond: Must send ETH to create bond");
        
        // Generate identity commitment from address and random secret
        identityCommitment = generateIdentityCommitment(msg.sender, randomSecret);
        
        // Ensure this identity hasn't been used before
        require(!usedIdentityCommitments[identityCommitment], "ElectoralBond: Identity already used");
        usedIdentityCommitments[identityCommitment] = true;
        
        // Generate nullifier hash from address and groupId
        nullifierHash = generateNullifierHash(msg.sender, groupId);
        
        require(!spentNullifiers[nullifierHash], "ElectoralBond: Nullifier already used");
        
        // Add to Semaphore group
        addMember(groupId, identityCommitment);
        
        // Map the nullifier to the bonded amount
        nullifierToAmount[nullifierHash] = msg.value;
        
        emit BondCreated( msg.value);
        
        return (identityCommitment, nullifierHash);
    }
    
    /**
     *  Generates an identity commitment from address and random secret
     */
    function generateIdentityCommitment(
        address account,
        bytes32 randomSecret
    ) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(account, randomSecret))) % SemaphoreCore.SNARK_SCALAR_FIELD;
    }
    
    /**
     * Generates a nullifier hash from address and groupId
     */
    function generateNullifierHash(
        address account,
        uint256 _groupId
    ) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(account, _groupId))) % SemaphoreCore.SNARK_SCALAR_FIELD;
    }

    /**
     *  Withdraw funds from an electoral bond using a zero-knowledge proof
     */

     function withdrawBond(
        uint256 nullifierHash,
        address recipient,
        uint256 amount,
        uint256 merkleTreeRoot,
        bytes32 signal,
        uint256[8] calldata proof
    ) external nonReentrant {
        require(!spentNullifiers[nullifierHash], "ElectoralBond: Nullifier already spent");
        require(amount > 0, "ElectoralBond: Withdrawal amount must be positive");
        require(
            nullifierToWithdrawn[nullifierHash] + amount <= nullifierToAmount[nullifierHash],
            "ElectoralBond: Withdrawal exceeds bond amount"
        );
        
        // Verify the Semaphore proof
        verifyProof(
            groupId,
            merkleTreeRoot,
            signal,
            nullifierHash,
            proof
        );
        
        // Mark the nullifier as spent (or partially spent)
        nullifierToWithdrawn[nullifierHash] += amount;
        
        // If the full amount is withdrawn, mark the nullifier as fully spent
        if (nullifierToWithdrawn[nullifierHash] == nullifierToAmount[nullifierHash]) {
            spentNullifiers[nullifierHash] = true;
        }
        
        // Transfer the funds to the recipient
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "ElectoralBond: ETH transfer failed");
        
        emit BondWithdrawn(nullifierHash, recipient, amount);
    }
    
    /**
     *  Get the remaining amount that can be withdrawn from a bond
     */
    function getRemainingAmount(uint256 nullifierHash) public view returns (uint256) {
        return nullifierToAmount[nullifierHash] - nullifierToWithdrawn[nullifierHash];
    }
    
    /**
     *  Get the total amount of a bond
     */
    function getBondAmount(uint256 nullifierHash) public view returns (uint256) {
        return nullifierToAmount[nullifierHash];
    }
}



