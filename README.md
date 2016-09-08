# Open Vote Network


What is the Open Vote Network?
=========================

The Open Vote Network is an online voting protocol that ensures the privacy of each vote, and removes the need for a tally authority. 

A description of the Anonymous Voting protocol can be found here:
http://homepages.cs.ncl.ac.uk/feng.hao/files/OpenVote_IET.pdf

Why Ethereum? 
==============

All communication must be public and authentication between the participants, and  a public bulletin board should be available to store the eligibility white list, voting keys and votes. 

Ethereum's underlying peer to peer network provides the public (and authenticated) communication channel, and its blockchain provides an immutable public ledger to store the voting information. 

Furthermore, Ethereum is a platform for 'Smart Contracts' that requires the peer to peer network, the economic majority, and the majority of miners to reach consensus on a program's execution. 
This allows the Smart Contract that governs the Open Vote Network to self-enforce the execution of the protocol, and allow anyone to verify that the protocol has executed correctly. 

How does it work? 
================

The protocol has six phases.

SETUP Phase. 

- Election Authority is responsible for sending Ethereum a white list of eligible voters.

SIGNUP Phase.

- Voters submit their voting key, and a zero knowledge prove to prove knowledge of the voting key's secret. 
- Ethereum verifies the correctness of the zero knowledge proof, and stores the voting key. 

COMPUTE Phase.

- Ethereum computes each voter's special reconstructed voting key.

VOTE Phase. 

- Voters submit their vote, and a 1 out of 2 zero knowledge proof that the vote is either 1 or 0. (i.e. yes or no). 
- Ethereum verifies the 1 out of 2 zero knowledge proof, and stores the vote.

TALLY Phase.

- Ethereum computes the tally once all votes have been cast. 

How can I pick up this library and go? 
=====================================

You need to run 'Geth' in the background:

1. geth <OPTIONAL: --dev/testnet> --rpc --rpcapi="db,eth,net,web3,personal" --rpcport "8545" --rpcaddr "127.0.0.1" --rpccorsdomain "*" console 
2. Compile the .SOL, and send it to the Ethereum Network. 
3. Update vote.html and admin.html with the correct abi/contract address. 
4. Voters open vote.html, and the Election Authority opens admin.html
5. Each voter requires a voter.txt document that contains the following:
 * x - the private key for the voter's voting key,
 * xG - the voter's voting public key, 
 * v - the random nonce for a single ZKP,
 * w,r,d - the random nonces for the 1 out of 2 ZKP.
 * All values should be seperated by commas (i.e. ",") in a .txt document. 
6. Voters can register and cast their vote.

An example 'voter.txt' has been included, and a Java Program 'votingcodes.jar' is included that can compute these numbers for the voter. 

What remains to be implemented?
============================

This library is still requires peer-review. Anyone is welcome to use the implementation, but it comes with no warranty, etc. 

Some small tasks that remain:
- Registration requires a deposit from voter which is refunded upon submitting a valid vote. 
- Voting and Admin pages require further work (i.e. 'Tally' button should only be usable when all votes have been cast). 
- Extend protocol to allow more than 40 voters. 

What functions are available? 
==============================

The voting protocol leverages the following libraries: 

ECCMath and Secp256k1: https://github.com/androlo/standard-contracts/blob/master/contracts/src/crypto/Secp256k1.sol
DateTimePicker: http://xdsoft.net/jqplugins/datetimepicker/

We have implemented the following:

### Schnorr non-interactive ZKP:

// Function should ONLY be called locally. NEVER send transaction to network. 
createZKP(uint x, uint v, uint[2] xG) 

// Send transaction to the network to allow Ethereum to verify 
verifyZKP(uint[2] xG, uint r, uint[3] vG) 

### 1 out of 2 ZKP:
// Function should ONLY be called locally. NEVER send transaction to network.
create1outof2ZKPYesVote(uint w, uint r1, uint d1, uint x)

// Function should ONLY be called locally. NEVER send transaction to network. 
create1outof2ZKPNoVote(uint w, uint r2, uint d2, uint x)

// Send transaction to the network to allow Ethereum to verify.
verify1outof2ZKP(uint[4] params, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) 

### Election Functions:

SETUP Phase

// White list a set of addresses. Only Election Authority can call. 
setEligible(address[] addr) 

// Set question and period of time for voters to sign up. Transition from SETUP to SIGNUP Phase. Only Election Authority can call. 
beginSignUp(uint time, string _question)

SIGNUP Phase
// Voters register their voting key. All eligible voters can call.
register(uint[2] xG, uint[3] vG, uint r) 

// Transition from SETUP to COMPUTE Phase. 
finishRegistrationPhase()

COMPUTE Phase

// Compute each voter's 'special voting key'. Only Election Authority can call. 
computeReconstructedPublicKeys() 

VOTE Phase

// Voters submit their vote. All registered votes can call.
submitVote(uint[4] params, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) 

// Compute the final tally. Anyone can call. Transition from VOTE Phase to FINISH Phase. 
computeTally() 

ANY Phase. 

// Reset the entire election. Only Election Authority can call. 
Reset() 

What is next? 
=============

We are currently writing up about this protocol and how it works with Ethereum. 

The code has been realised early as for us to test on Ethereum's real network will require our code to be made public regardless. 
