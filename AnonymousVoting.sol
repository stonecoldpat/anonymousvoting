/**
 * @title ECCMath
 *
 * Functions for working with integers, curve-points, etc.
 *
 * @author Andreas Olofsson (androlo1980@gmail.com)
 */
library ECCMath {
    /// @dev Modular inverse of a (mod p) using euclid.
    /// "a" and "p" must be co-prime.
    /// @param a The number.
    /// @param p The mmodulus.
    /// @return x such that ax = 1 (mod p)
    function invmod(uint a, uint p) internal constant returns (uint) {
        if (a == 0 || a == p || p == 0)
            throw;
        if (a > p)
            a = a % p;
        int t1;
        int t2 = 1;
        uint r1 = p;
        uint r2 = a;
        uint q;
        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
        }
        if (t1 < 0)
            return (p - uint(-t1));
        return uint(t1);
    }

    /// @dev Modular exponentiation, b^e % m
    /// Basically the same as can be found here:
    /// https://github.com/ethereum/serpent/blob/develop/examples/ecc/modexp.se
    /// @param b The base.
    /// @param e The exponent.
    /// @param m The modulus.
    /// @return x such that x = b**e (mod m)
    function expmod(uint b, uint e, uint m) internal constant returns (uint r) {
        if (b == 0)
            return 0;
        if (e == 0)
            return 1;
        if (m == 0)
            throw;
        r = 1;
        uint bit = 2 ** 255;
        assembly {
            loop:
                jumpi(end, iszero(bit))
                r := mulmod(mulmod(r, r, m), exp(b, iszero(iszero(and(e, bit)))), m)
                r := mulmod(mulmod(r, r, m), exp(b, iszero(iszero(and(e, div(bit, 2))))), m)
                r := mulmod(mulmod(r, r, m), exp(b, iszero(iszero(and(e, div(bit, 4))))), m)
                r := mulmod(mulmod(r, r, m), exp(b, iszero(iszero(and(e, div(bit, 8))))), m)
                bit := div(bit, 16)
                jump(loop)
            end:
        }
    }

    /// @dev Converts a point (Px, Py, Pz) expressed in Jacobian coordinates to (Px", Py", 1).
    /// Mutates P.
    /// @param P The point.
    /// @param zInv The modular inverse of "Pz".
    /// @param z2Inv The square of zInv
    /// @param prime The prime modulus.
    /// @return (Px", Py", 1)
    function toZ1(uint[3] memory P, uint zInv, uint z2Inv, uint prime) internal constant {
        P[0] = mulmod(P[0], z2Inv, prime);
        P[1] = mulmod(P[1], mulmod(zInv, z2Inv, prime), prime);
        P[2] = 1;
    }

    /// @dev See _toZ1(uint[3], uint, uint).
    /// Warning: Computes a modular inverse.
    /// @param PJ The point.
    /// @param prime The prime modulus.
    /// @return (Px", Py", 1)
    function toZ1(uint[3] PJ, uint prime) internal constant {
        uint zInv = invmod(PJ[2], prime);
        uint zInv2 = mulmod(zInv, zInv, prime);
        PJ[0] = mulmod(PJ[0], zInv2, prime);
        PJ[1] = mulmod(PJ[1], mulmod(zInv, zInv2, prime), prime);
        PJ[2] = 1;
    }

}

library Secp256k1 {

    // TODO separate curve from crypto primitives?

    // Field size
    uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // Order of G
    uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Cofactor
    // uint constant hh = 1;

    // Maximum value of s
    uint constant lowSmax = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // For later
    // uint constant lambda = "0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72";
    // uint constant beta = "0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";

    /// @dev See Curve.onCurve
    function onCurve(uint[2] P) internal constant returns (bool) {
        uint p = pp;
        if (0 == P[0] || P[0] == p || 0 == P[1] || P[1] == p)
            return false;
        uint LHS = mulmod(P[1], P[1], p);
        uint RHS = addmod(mulmod(mulmod(P[0], P[0], p), P[0], p), 7, p);
        return LHS == RHS;
    }

    /// @dev See Curve.isPubKey
    function isPubKey(uint[2] memory P) internal constant returns (bool isPK) {
        isPK = onCurve(P);
    }

    /// @dev See Curve.isPubKey
    // TODO: We assume we are given affine co-ordinates for now
    function isPubKey(uint[3] memory P) internal constant returns (bool isPK) {
        uint[2] memory a_P;
        a_P[0] = P[0];
        a_P[1] = P[1];
        isPK = onCurve(a_P);
    }

    /// @dev See Curve.validateSignature
    function validateSignature(bytes32 message, uint[2] rs, uint[2] Q) internal constant returns (bool) {
        uint n = nn;
        uint p = pp;
        if(rs[0] == 0 || rs[0] >= n || rs[1] == 0 || rs[1] > lowSmax)
            return false;
        if (!isPubKey(Q))
            return false;

        uint sInv = ECCMath.invmod(rs[1], n);
        uint[3] memory u1G = _mul(mulmod(uint(message), sInv, n), [Gx, Gy]);
        uint[3] memory u2Q = _mul(mulmod(rs[0], sInv, n), Q);
        uint[3] memory P = _add(u1G, u2Q);

        if (P[2] == 0)
            return false;

        uint Px = ECCMath.invmod(P[2], p); // need Px/Pz^2
        Px = mulmod(P[0], mulmod(Px, Px, p), p);
        return Px % n == rs[0];
    }

    /// @dev See Curve.compress
    function compress(uint[2] P) internal constant returns (uint8 yBit, uint x) {
        x = P[0];
        yBit = P[1] & 1 == 1 ? 1 : 0;
    }

    /// @dev See Curve.decompress
    function decompress(uint8 yBit, uint x) internal constant returns (uint[2] P) {
        uint p = pp;
        var y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
        var y_ = ECCMath.expmod(y2, (p + 1) / 4, p);
        uint cmp = yBit ^ y_ & 1;
        P[0] = x;
        P[1] = (cmp == 0) ? y_ : p - y_;
    }

    // Point addition, P + Q
    // inData: Px, Py, Pz, Qx, Qy, Qz
    // outData: Rx, Ry, Rz
    function _add(uint[3] memory P, uint[3] memory Q) internal constant returns (uint[3] memory R) {
        if(P[2] == 0)
            return Q;
        if(Q[2] == 0)
            return P;
        uint p = pp;
        uint[4] memory zs; // Pz^2, Pz^3, Qz^2, Qz^3
        zs[0] = mulmod(P[2], P[2], p);
        zs[1] = mulmod(P[2], zs[0], p);
        zs[2] = mulmod(Q[2], Q[2], p);
        zs[3] = mulmod(Q[2], zs[2], p);
        uint[4] memory us = [
            mulmod(P[0], zs[2], p),
            mulmod(P[1], zs[3], p),
            mulmod(Q[0], zs[0], p),
            mulmod(Q[1], zs[1], p)
        ]; // Pu, Ps, Qu, Qs
        if (us[0] == us[2]) {
            if (us[1] != us[3])
                return;
            else {
                return _double(P);
            }
        }
        uint h = addmod(us[2], p - us[0], p);
        uint r = addmod(us[3], p - us[1], p);
        uint h2 = mulmod(h, h, p);
        uint h3 = mulmod(h2, h, p);
        uint Rx = addmod(mulmod(r, r, p), p - h3, p);
        Rx = addmod(Rx, p - mulmod(2, mulmod(us[0], h2, p), p), p);
        R[0] = Rx;
        R[1] = mulmod(r, addmod(mulmod(us[0], h2, p), p - Rx, p), p);
        R[1] = addmod(R[1], p - mulmod(us[1], h3, p), p);
        R[2] = mulmod(h, mulmod(P[2], Q[2], p), p);
    }

    // Point addition, P + Q. P Jacobian, Q affine.
    // inData: Px, Py, Pz, Qx, Qy
    // outData: Rx, Ry, Rz
    function _addMixed(uint[3] memory P, uint[2] memory Q) internal constant returns (uint[3] memory R) {
        if(P[2] == 0)
            return [Q[0], Q[1], 1];
        if(Q[1] == 0)
            return P;
        uint p = pp;
        uint[2] memory zs; // Pz^2, Pz^3, Qz^2, Qz^3
        zs[0] = mulmod(P[2], P[2], p);
        zs[1] = mulmod(P[2], zs[0], p);
        uint[4] memory us = [
            P[0],
            P[1],
            mulmod(Q[0], zs[0], p),
            mulmod(Q[1], zs[1], p)
        ]; // Pu, Ps, Qu, Qs
        if (us[0] == us[2]) {
            if (us[1] != us[3]) {
                P[0] = 0;
                P[1] = 0;
                P[2] = 0;
                return;
            }
            else {
                _double(P);
                return;
            }
        }
        uint h = addmod(us[2], p - us[0], p);
        uint r = addmod(us[3], p - us[1], p);
        uint h2 = mulmod(h, h, p);
        uint h3 = mulmod(h2, h, p);
        uint Rx = addmod(mulmod(r, r, p), p - h3, p);
        Rx = addmod(Rx, p - mulmod(2, mulmod(us[0], h2, p), p), p);
        R[0] = Rx;
        R[1] = mulmod(r, addmod(mulmod(us[0], h2, p), p - Rx, p), p);
        R[1] = addmod(R[1], p - mulmod(us[1], h3, p), p);
        R[2] = mulmod(h, P[2], p);
    }

    // Same as addMixed but params are different and mutates P.
    function _addMixedM(uint[3] memory P, uint[2] memory Q) internal constant {
        if(P[1] == 0) {
            P[0] = Q[0];
            P[1] = Q[1];
            P[2] = 1;
            return;
        }
        if(Q[1] == 0)
            return;
        uint p = pp;
        uint[2] memory zs; // Pz^2, Pz^3, Qz^2, Qz^3
        zs[0] = mulmod(P[2], P[2], p);
        zs[1] = mulmod(P[2], zs[0], p);
        uint[4] memory us = [
            P[0],
            P[1],
            mulmod(Q[0], zs[0], p),
            mulmod(Q[1], zs[1], p)
        ]; // Pu, Ps, Qu, Qs
        if (us[0] == us[2]) {
            if (us[1] != us[3]) {
                P[0] = 0;
                P[1] = 0;
                P[2] = 0;
                return;
            }
            else {
                _doubleM(P);
                return;
            }
        }
        uint h = addmod(us[2], p - us[0], p);
        uint r = addmod(us[3], p - us[1], p);
        uint h2 = mulmod(h, h, p);
        uint h3 = mulmod(h2, h, p);
        uint Rx = addmod(mulmod(r, r, p), p - h3, p);
        Rx = addmod(Rx, p - mulmod(2, mulmod(us[0], h2, p), p), p);
        P[0] = Rx;
        P[1] = mulmod(r, addmod(mulmod(us[0], h2, p), p - Rx, p), p);
        P[1] = addmod(P[1], p - mulmod(us[1], h3, p), p);
        P[2] = mulmod(h, P[2], p);
    }

    // Point doubling, 2*P
    // Params: Px, Py, Pz
    // Not concerned about the 1 extra mulmod.
    function _double(uint[3] memory P) internal constant returns (uint[3] memory Q) {
        uint p = pp;
        if (P[2] == 0)
            return;
        uint Px = P[0];
        uint Py = P[1];
        uint Py2 = mulmod(Py, Py, p);
        uint s = mulmod(4, mulmod(Px, Py2, p), p);
        uint m = mulmod(3, mulmod(Px, Px, p), p);
        var Qx = addmod(mulmod(m, m, p), p - addmod(s, s, p), p);
        Q[0] = Qx;
        Q[1] = addmod(mulmod(m, addmod(s, p - Qx, p), p), p - mulmod(8, mulmod(Py2, Py2, p), p), p);
        Q[2] = mulmod(2, mulmod(Py, P[2], p), p);
    }

    // Same as double but mutates P and is internal only.
    function _doubleM(uint[3] memory P) internal constant {
        uint p = pp;
        if (P[2] == 0)
            return;
        uint Px = P[0];
        uint Py = P[1];
        uint Py2 = mulmod(Py, Py, p);
        uint s = mulmod(4, mulmod(Px, Py2, p), p);
        uint m = mulmod(3, mulmod(Px, Px, p), p);
        var PxTemp = addmod(mulmod(m, m, p), p - addmod(s, s, p), p);
        P[0] = PxTemp;
        P[1] = addmod(mulmod(m, addmod(s, p - PxTemp, p), p), p - mulmod(8, mulmod(Py2, Py2, p), p), p);
        P[2] = mulmod(2, mulmod(Py, P[2], p), p);
    }

    // Multiplication dP. P affine, wNAF: w=5
    // Params: d, Px, Py
    // Output: Jacobian Q
    function _mul(uint d, uint[2] memory P) internal constant returns (uint[3] memory Q) {
        uint p = pp;
        if (d == 0) // TODO
            return;
        uint dwPtr; // points to array of NAF coefficients.
        uint i;

        // wNAF
        assembly
        {
                let dm := 0
                dwPtr := mload(0x40)
                mstore(0x40, add(dwPtr, 512)) // Should lower this.
            loop:
                jumpi(loop_end, iszero(d))
                jumpi(even, iszero(and(d, 1)))
                dm := mod(d, 32)
                mstore8(add(dwPtr, i), dm) // Don"t store as signed - convert when reading.
                d := add(sub(d, dm), mul(gt(dm, 16), 32))
            even:
                d := div(d, 2)
                i := add(i, 1)
                jump(loop)
            loop_end:
        }

        // Pre calculation
        uint[3][8] memory PREC; // P, 3P, 5P, 7P, 9P, 11P, 13P, 15P
        PREC[0] = [P[0], P[1], 1];
        var X = _double(PREC[0]);
        PREC[1] = _addMixed(X, P);
        PREC[2] = _add(X, PREC[1]);
        PREC[3] = _add(X, PREC[2]);
        PREC[4] = _add(X, PREC[3]);
        PREC[5] = _add(X, PREC[4]);
        PREC[6] = _add(X, PREC[5]);
        PREC[7] = _add(X, PREC[6]);

        uint[16] memory INV;
        INV[0] = PREC[1][2];                            // a1
        INV[1] = mulmod(PREC[2][2], INV[0], p);         // a2
        INV[2] = mulmod(PREC[3][2], INV[1], p);         // a3
        INV[3] = mulmod(PREC[4][2], INV[2], p);         // a4
        INV[4] = mulmod(PREC[5][2], INV[3], p);         // a5
        INV[5] = mulmod(PREC[6][2], INV[4], p);         // a6
        INV[6] = mulmod(PREC[7][2], INV[5], p);         // a7

        INV[7] = ECCMath.invmod(INV[6], p);             // a7inv
        INV[8] = INV[7];                                // aNinv (a7inv)

        INV[15] = mulmod(INV[5], INV[8], p);            // z7inv
        for(uint k = 6; k >= 2; k--) {                  // z6inv to z2inv
            INV[8] = mulmod(PREC[k + 1][2], INV[8], p);
            INV[8 + k] = mulmod(INV[k - 2], INV[8], p);
        }
        INV[9] = mulmod(PREC[2][2], INV[8], p);         // z1Inv
        for(k = 0; k < 7; k++) {
            ECCMath.toZ1(PREC[k + 1], INV[k + 9], mulmod(INV[k + 9], INV[k + 9], p), p);
        }

        // Mult loop
        while(i > 0) {
            uint dj;
            uint pIdx;
            i--;
            assembly {
                dj := byte(0, mload(add(dwPtr, i)))
            }
            _doubleM(Q);
            if (dj > 16) {
                pIdx = (31 - dj) / 2; // These are the "negative ones", so invert y.
                _addMixedM(Q, [PREC[pIdx][0], p - PREC[pIdx][1]]);
            }
            else if (dj > 0) {
                pIdx = (dj - 1) / 2;
                _addMixedM(Q, [PREC[pIdx][0], PREC[pIdx][1]]);
            }
        }
    }

}


contract owned {
    address public owner;

    /* Initialise contract creator as owner */
    function owned() {
        owner = msg.sender;
    }

    /* Function to dictate that only the designated owner can call a function */
	  modifier onlyOwner {
        if(owner != msg.sender) throw;
        _
    }

    /* Transfer ownership of this contract to someone else */
    function transferOwnership(address newOwner) onlyOwner() {
        owner = newOwner;
    }
}

contract AnonymousVoting is owned {

  event Eligible(address addr);
  event StartTimer(string message, uint timestamp, uint current_timestamp);
  event Registered(address addr, bool res, uint counter);
  event RegistrationFinished();
  event ReconstructedKey(uint x, uint y, uint counter);
  event RegisterVote(address addr, bool res, uint counter);
  event Tally(uint tally, uint counter);

  // Modulus for public keys
  uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

  // Base point (generator) G
  uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

  // Modulus for private keys (sub-group)
  uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  uint[2] G;

  //Every address has an index
  //This makes looping in the program easier.
  address[] public addresses;
  mapping (address => uint) public addressid; // Address to Counter
  mapping (uint => Voter) voters;
  mapping (address => bool) public eligible; // White list of addresses allowed to vote
  mapping (address => bool) public registered; // Address registered?
  mapping (address => bool) public votecast; // Address voted?

// TODO: We can have a struct to represent a voters keys... but
// will need to re-organise large parts of the code..
// as users are currently represented as an int...
// is it worth the work?
  struct Voter {
      address addr;
      uint[2] registeredkey;
      uint[2] reconstructedkey;
      uint[2] vote;
  }

  uint public counter; //Total number of participants that have submited a voting key
  uint public timer; // Period of time until the voting phase can begin.
  string public question;
  uint[2] public finaltally; // Final tally

  enum State { SETUP, SIGNUP, COMPUTE, VOTE, FINISHED }
  State public state;

  modifier inState(State s) {
    if(state != s) {
        throw;
    }

    _
  }

  // 2 round anonymous voting protocol
  // TODO: Right now due to gas limits there is an upper limit
  // on the number of participants that we can have voting...
  // I need to split the functions up... so if they cannot
  // finish their entire workload in 1 transaction, then
  // it does the maximum. This way we can chain transactions
  // to complete the job...
  function AnonymousVoting() {
    G[0] = Gx;
    G[1] = Gy;
    counter = 0;
    state = State.SETUP;
    question = "No question set";
  }

  // We need to clear all the variables we stored for this election
  // Can be run at ANY time... esp if someone refuses to submit their vote.
  function reset() onlyOwner {
    uint[2] memory empty;

    for(uint i=0; i<addresses.length; i++) {
       address addr = addresses[i];
       eligible[addr] = false; // No longer eligible
       registered[addr] = false; // Remove voting registration
       voters[i] = Voter({addr: 0, registeredkey: empty, reconstructedkey: empty, vote: empty});
       addressid[addr] = 0; // Remove index
       votecast[addr] = false; // Remove that vote was cast
    }

    delete addresses;
    counter = 0;
    timer = 0;
    question = "No question set";
    finaltally[0] = 0;
    finaltally[1] = 0;

    // We are finished resetting.
    state = State.SETUP;
  }

  // Owner of contract sets a whitelist of addresses that are eligible to vote.
  function setEligible(address[] addr) onlyOwner {

    // We can only handle up to about 35-40 people at the moment.
    if(addresses.length + addr.length > 40) {
      throw;
    }

    // Sign up the addresses
    for(uint i=0; i<addr.length; i++) {

      if(!eligible[addr[i]]) {
        eligible[addr[i]] = true;
        addresses.push(addr[i]);
        Eligible(addr[i]);
      }
    }
  }

  // Owner of contract declares that eligible addresses begin round 1 of the protocol
  // Time is the number of 'blocks' we must wait until we can move onto round 2.
  function beginSignUp(uint time, string _question) inState(State.SETUP) onlyOwner {

    if(time > 1) {
      state = State.SIGNUP;
      timer = time; // Should be in UNIX
      question = _question;

      StartTimer("The sign up round has begun. Please submit your voting key.", timer, block.timestamp);
      return;
    }

    throw;
  }

  // Called by participants to register their voting public key
  // Participant mut be eligible, and can only register the first key sent key.
  function register(uint[2] xG, uint[3] vG, uint r) inState(State.SIGNUP) returns (bool) {

    // Only white-listed addresses can vote
    if(eligible[msg.sender]) {
        if(verifyZKP(xG,r,vG) && !registered[msg.sender]) {
            uint[2] memory empty;
            Registered(msg.sender, true, counter);
            addressid[msg.sender] = counter;
            voters[counter] = Voter({addr: msg.sender, registeredkey: xG, reconstructedkey: empty, vote: empty});
            registered[msg.sender] = true;
            counter += 1;

            return true;
        }
    }

    Registered(msg.sender, false, counter);
    return false;
  }


  // Timer has expired - we want to start computing the reconstructed keys
  function finishRegistrationPhase() inState(State.SIGNUP) onlyOwner {

     // We can only compute the public keys once participants
     // have been given an opportunity to regstier their
     // voting public key.
     if(block.timestamp < timer) {
       return;
     }

     // Make sure at least 3 people have signed up...
     if(counter < 3) {
       return;
     }

     state = State.COMPUTE;
     RegistrationFinished();
  }


  // Once the sign up phase is ready to end...
  // We must compute each participant's g^{y} which is a
  // "reconstructed public key". It is used as part of the
  // protocol's cancellation later on - which ultimately
  // leaks the tally!
  // Debate: Should this be an onlyOwner function?
  function computeReconstructedPublicKeys() inState(State.COMPUTE) onlyOwner {

    uint[2] memory temp;
    uint[3] memory yG;
    uint[3] memory beforei;
    uint[3] memory afteri;

    // Step 1 is to compute the index 1 reconstructed key
    afteri[0] = voters[1].registeredkey[0];
    afteri[1] = voters[1].registeredkey[1];
    afteri[2] = 1;

    for(uint i=2; i<counter; i++) {

       Secp256k1._addMixedM(afteri, voters[i].registeredkey);
    }

    ECCMath.toZ1(afteri,pp);
    voters[0].reconstructedkey[0] = afteri[0];
    voters[0].reconstructedkey[1] = pp - afteri[1];
    ReconstructedKey(voters[0].reconstructedkey[0], voters[0].reconstructedkey[1], 0);

    // Step 2 is to add to beforei, and subtract from afteri.
   for(i=1; i<counter; i++) {

     if(i==1) {
       beforei[0] = voters[0].registeredkey[0];
       beforei[1] = voters[0].registeredkey[1];
       beforei[2] = 1;
     } else {
       Secp256k1._addMixedM(beforei, voters[i-1].registeredkey);
     }

     // If we have reached the end... just store beforei
     // Otherwise, we need to compute a key.
     // Counting from 0 to n-1...
     if(i==(counter-1)) {
       ECCMath.toZ1(beforei,pp);
       voters[i].reconstructedkey[0] = beforei[0];
       voters[i].reconstructedkey[1] = beforei[1];

     } else {

        // Subtract 'i' from afteri
        temp[0] = voters[i].registeredkey[0];
        temp[1] = pp - voters[i].registeredkey[1];

        // Grab negation of afteri (did not seem to work with Jacob co-ordinates)
        Secp256k1._addMixedM(afteri,temp);
        ECCMath.toZ1(afteri,pp);

        temp[0] = afteri[0];
        temp[1] = pp - afteri[1];

        // Now we do beforei - afteri...
        yG = Secp256k1._addMixed(beforei, temp);

        ECCMath.toZ1(yG,pp);

        voters[i].reconstructedkey[0] = yG[0];
        voters[i].reconstructedkey[1] = yG[1];
     }

     ReconstructedKey(voters[i].reconstructedkey[0], voters[i].reconstructedkey[1], i);
   }

    // Finally we are reading to enter the voting state
    state = State.VOTE;
  }

  //Given the 1 out of 2 ZKP - record the users vote!
  function submitVote(uint[4] params, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) inState(State.VOTE) returns (bool){

     uint c = addressid[msg.sender];

     // Make sure the sender can vote, and hasn't already voted.
     if(registered[msg.sender] && !votecast[msg.sender]) {

       // Verify the ZKP for the vote being cast
       if(verify1outof2ZKP(params, c, y, a1, b1, a2, b2)) {
         voters[c].vote[0] = y[0];
         voters[c].vote[1] = y[1];

         votecast[msg.sender] = true;
         RegisterVote(msg.sender, votecast[msg.sender], c);
         return true;
       }
     }

     // Either vote has already been cast, or ZKP verification failed.
     RegisterVote(msg.sender, false, c);
     return false;
  }

  // Assuming all votes have been submitted. We can leak the tally.
  // Anyone can close the election. No need for Election Authority to do it.
  // TODO: Allow someone to submit the tally and to verify it here. Would be cheaper!
  function computeTally() inState(State.VOTE) returns (uint[2]){

     uint[3] memory temp;
     uint[2] memory vote;

     // Sum all votes
     for(uint i=0; i<counter; i++) {

         // Confirm all votes have been cast...
         if(!votecast[voters[i].addr]) {
            throw;
         }

         vote = voters[i].vote;

         if(i==0) {
           temp[0] = vote[0];
           temp[1] = vote[1];
           temp[2] = 1;
         } else {
             Secp256k1._addMixedM(temp, vote);
         }
     }

     // All votes have been accounted for...
     // Get tally, and change state to 'Finished'
     state = State.FINISHED;

     // Each vote is represented by a G.
     // If there are no votes... then it is 0G = (0,0)...
     if(temp[0] == 0) {
       finaltally[0] = 0;
       finaltally[1] = counter;
       Tally(0,counter);
       return;
     } else {

       // There must be a vote. So lets
       // start adding 'G' until we
       // find the result.
       ECCMath.toZ1(temp,pp);
       uint[3] memory tempG;
       tempG[0] = G[0];
       tempG[1] = G[1];
       tempG[2] = 1;

       // Start adding 'G' and looking for a match
       for(i=1; i<=counter; i++) {

         if(temp[0] == tempG[0]) {
             finaltally[0] = i;
             finaltally[1] = counter;
             Tally(i,counter);
             return;
         }

         // If something bad happens and we cannot find the Tally
         // Then this 'addition' will be run 1 extra time due to how
         // we have structured the for loop.
         // TODO: Does it need fixed?
         Secp256k1._addMixedM(tempG, G);
         ECCMath.toZ1(tempG,pp);
       }

       // Something bad happened. We should never get here....
       // This represents an error message... best telling people
       // As we cannot recover from it anyway.
       // TODO: Handle this better....
       finaltally[0] = 0;
       finaltally[1] = 0;
       Tally(0,0);
       return;
     }
  }

  // vG (blinding value), xG (public key), x (what we are proving)
  // c = H(g, g^{v}, g^{x});
  // r = v - xz (mod p);
  // return(r,vG)
  function createZKP(uint x, uint v, uint[2] xG) returns (uint[4] res) {

     uint[2] memory G;
     G[0] = Gx;
     G[1] = Gy;

     if(!Secp256k1.isPubKey(xG)) {
       throw; //Must be on the curve!
     }

     // Get g^{v}
     uint[3] memory vG = Secp256k1._mul(v, G);

     // Convert to Affine Co-ordinates
     ECCMath.toZ1(vG, pp);

     // Get c = H(g, g^{x}, g^{v});
     bytes32 b_c = sha256(Gx, Gy, xG[0], xG[1], vG[0], vG[1]);
     uint c = uint(b_c);

     // Get 'r' the zkp
     uint xc = mulmod(x,c,nn);
     uint addv;

     // We are working with unsigned integers... so lets not loop around
     // TODO: Seek help so we do not need the if statement
     // I am basically doing submod?
     if(v>xc) {
       addv = v;
     } else {
       addv = v+nn;
     }

     // v - xc
     uint r = addmod(addv - xc,0,nn);

     res[0] = r;
     res[1] = vG[0];
     res[2] = vG[1];
     res[3] = vG[2];
     return res;
  }

  // a - b = c;
  function submod(uint a, uint b) returns (uint){
    uint a_nn;

    if(a>b) {
      a_nn = a;
    } else {
      a_nn = a+nn;
    }

    uint c = addmod(a_nn - b,0,nn);

    return c;
  }

  // Parameters xG, r where r = v - xc, and vG.
  // Verify that vG = rG + xcG!
  function verifyZKP(uint[2] xG, uint r, uint[3] vG) returns (bool){
    uint[2] memory G;
    G[0] = Gx;
    G[1] = Gy;

    // Check both keys are on the curve.
    if(!Secp256k1.isPubKey(xG) || !Secp256k1.isPubKey(vG)) {
      throw; //Must be on the curve!
    }

    // Get c = H(g, g^{x}, g^{v});
    bytes32 b_c = sha256(Gx, Gy, xG, vG[0], vG[1]);
    uint c = uint(b_c);

    // Get g^{r}, and g^{xc}
    uint[3] memory rG = Secp256k1._mul(r, G);
    uint[3] memory xcG = Secp256k1._mul(c, xG);

    // Add both points together
    uint[3] memory rGxcG = Secp256k1._add(rG,xcG);

    // Convert to Affine Co-ordinates
    ECCMath.toZ1(rGxcG, pp);

    // Verify. Do they match?
    if(rGxcG[0] == vG[0] && rGxcG[1] == vG[1]) {
       return true;
    } else {
      return false;
    }
  }

  // random 'w', 'r1', 'd1'
  // TODO: Make constant
  function create1outof2ZKPYesVote(uint w, uint i, uint r1, uint d1, uint x) returns (uint[10] res, uint[4] res2){
    uint[2] memory temp;

    uint[2] memory yG = voters[i].reconstructedkey;
    uint[2] memory xG = voters[i].registeredkey;

    // y = h^{x} * g
    uint[3] memory temp1 = Secp256k1._mul(x,yG);
    Secp256k1._addMixedM(temp1,G);
    ECCMath.toZ1(temp1, pp);
    res[0] = temp1[0];
    res[1] = temp1[1];

    // a1 = g^{r1} * x^{d1}
    temp1 = Secp256k1._mul(r1,G);
    temp1 = Secp256k1._add(temp1, Secp256k1._mul(d1,xG));
    ECCMath.toZ1(temp1, pp);
    res[2] = temp1[0];
    res[3] = temp1[1];

    // b1 = h^{r1} * y^{d1} (temp = affine 'y')
    temp1 = Secp256k1._mul(r1,yG);

    // Setting temp to 'y'
    temp[0] = res[0];
    temp[1] = res[1];
    temp1= Secp256k1._add(temp1, Secp256k1._mul(d1, temp));
    ECCMath.toZ1(temp1, pp);
    res[4] = temp1[0];
    res[5] = temp1[1];

    // a2 = g^{w}
    temp1 = Secp256k1._mul(w,G);
    ECCMath.toZ1(temp1, pp);

    res[6] = temp1[0];
    res[7] = temp1[1];

    // b2 = h^{w} (where h = g^{y})
    temp1 = Secp256k1._mul(w, yG);
    ECCMath.toZ1(temp1, pp);
    res[8] = temp1[0];
    res[9] = temp1[1];

    // Get c = H(i, x, y, a1, b1, a2, b2);
    bytes32 b_c = sha256(i, xG[0], xG[1], res);
    uint c = uint(b_c);

    // d2 = c - d1 mod q
    temp[0] = submod(c,d1);

    // r2 = w - (x * d2)
    temp[1] = submod(w, mulmod(x,temp[0],nn));

    /* We return the following
    * res[0] = y_x;
    * res[1] = y_y;
    * res[2] = a1_x;
    * res[3] = a1_y;
    * res[4] = b1_x;
    * res[5] = b1_y;
    * res[6] = a2_x;
    * res[7] = a2_y;
    * res[8] = b2_x;
    * res[9] = b2_y;
    * res[10] = d1;
    * res[11] = d2;
    * res[12] = r1;
    * res[13] = r2;
    */
    res2[0] = d1;
    res2[1] = temp[0];
    res2[2] = r1;
    res2[3] = temp[1];
  }

  // random 'w', 'r1', 'd1'
  function create1outof2ZKPNoVote(uint w, uint i, uint r2, uint d2, uint x) returns (uint[10] res, uint[4] res2){
      uint[2] memory temp_affine1;
      uint[2] memory temp_affine2;

      uint[2] memory yG = voters[i].reconstructedkey;
      uint[2] memory xG = voters[i].registeredkey;

      // y = h^{x} * g
      uint[3] memory temp1 = Secp256k1._mul(x,yG);
      ECCMath.toZ1(temp1, pp);

      // Store y_x and y_y
      res[0] = temp1[0];
      res[1] = temp1[1];

      // a1 = g^{w}
      temp1 = Secp256k1._mul(w,G);
      ECCMath.toZ1(temp1, pp);

      // Store a1_x and a1_y
      res[2] = temp1[0];
      res[3] = temp1[1];

      // b1 = h^{w} (where h = g^{y})
      temp1 = Secp256k1._mul(w, yG);
      ECCMath.toZ1(temp1, pp);

      res[4] = temp1[0];
      res[5] = temp1[1];

      // a2 = g^{r2} * x^{d2}
      temp1 = Secp256k1._mul(r2,G);
      temp1 = Secp256k1._add(temp1, Secp256k1._mul(d2,xG));
      ECCMath.toZ1(temp1, pp);

      res[6] = temp1[0];
      res[7] = temp1[1];

      // Negate the 'y' co-ordinate of G
      temp_affine1[0] = G[0];
      temp_affine1[1] = pp - G[1];

      // We need the public key y in affine co-ordinates
      temp_affine2[0] = res[0];
      temp_affine2[1] = res[1];

      // We should end up with y^{d2} + g^{d2} .... (but we have the negation of g.. so y-g).
      temp1 = Secp256k1._add(Secp256k1._mul(d2,temp_affine2), Secp256k1._mul(d2,temp_affine1));

      // Now... it is h^{r2} + temp2..
      temp1 = Secp256k1._add(Secp256k1._mul(r2,yG),temp1);
      // Convert to Affine Co-ordinates
      ECCMath.toZ1(temp1, pp);

      res[8] = temp1[0];
      res[9] = temp1[1];

      // Get c = H(i, x, y, a1, b1, a2, b2);
      bytes32 b_c = sha256(i, xG[0], xG[1], res);
      uint c = uint(b_c);

      // d1 = c - d2 mod q
      temp1[0] = submod(c,d2);

      // r1 = w - (x * d1)
      temp1[1] = submod(w, mulmod(x,temp1[0],nn));

      /* We return the following
      * res[0] = y_x;
      * res[1] = y_y;
      * res[2] = a1_x;
      * res[3] = a1_y;
      * res[4] = b1_x;
      * res[5] = b1_y;
      * res[6] = a2_x;
      * res[7] = a2_y;
      * res[8] = b2_x;
      * res[9] = b2_y;
      * res[10] = d1;
      * res[11] = d2;
      * res[12] = r1;
      * res[13] = r2;
      */
      res2[0] = temp1[0];
      res2[1] = d2;
      res2[2] = temp1[1];
      res2[3] = r2;
    }

  // We verify that the ZKP is of 0 or 1.
  function verify1outof2ZKP(uint[4] params, uint i, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bool) {
      uint[2] memory temp1;
      uint[3] memory temp2;
      uint[3] memory temp3;

      // We already have them stored...
      // TODO: Decide if this should be in SubmitVote or here...
      uint[2] memory yG = voters[i].reconstructedkey;
      uint[2] memory xG = voters[i].registeredkey;

      // Make sure we are only dealing with valid public keys!
      if(!Secp256k1.isPubKey(xG) || !Secp256k1.isPubKey(yG) || !Secp256k1.isPubKey(y) || !Secp256k1.isPubKey(a1) ||
         !Secp256k1.isPubKey(b1) || !Secp256k1.isPubKey(a2) || !Secp256k1.isPubKey(b2)) {
         throw;
      }

      // Does c =? d1 + d2 (mod n)
      if(uint(sha256(i, xG, y, a1, b1, a2, b2)) != addmod(params[0],params[1],nn)) {
        return false;
      }

      // a1 =? g^{r1} * x^{d1}
      temp2 = Secp256k1._mul(params[2], G);
      temp3 = Secp256k1._add(temp2, Secp256k1._mul(params[0], xG));
      ECCMath.toZ1(temp3, pp);

      if(a1[0] != temp3[0] || a1[1] != temp3[1]) {
        return false;
      }

      //b1 =? h^{r1} * y^{d1} (temp = affine 'y')
      temp2 = Secp256k1._mul(params[2],yG);
      temp3 = Secp256k1._add(temp2, Secp256k1._mul(params[0], y));
      ECCMath.toZ1(temp3, pp);

      if(b1[0] != temp3[0] || b1[1] != temp3[1]) {
        return false;
      }

      //a2 =? g^{r2} * x^{d2}
      temp2 = Secp256k1._mul(params[3],G);
      temp3 = Secp256k1._add(temp2, Secp256k1._mul(params[1], xG));
      ECCMath.toZ1(temp3, pp);

      if(a2[0] != temp3[0] || a2[1] != temp3[1]) {
        return false;
      }

      // Negate the 'y' co-ordinate of g
      temp1[0] = G[0];
      temp1[1] = pp - G[1];

      // get 'y'
      temp3[0] = y[0];
      temp3[1] = y[1];
      temp3[2] = 1;

      // y-g
      temp2 = Secp256k1._addMixed(temp3,temp1);

      // Return to affine co-ordinates
      ECCMath.toZ1(temp2, pp);
      temp1[0] = temp2[0];
      temp1[1] = temp2[1];

      // (y-g)^{d2}
      temp2 = Secp256k1._mul(params[1],temp1);

      // Now... it is h^{r2} + temp2..
      temp3 = Secp256k1._add(Secp256k1._mul(params[3],yG),temp2);

      // Convert to Affine Co-ordinates
      ECCMath.toZ1(temp3, pp);

      // Should all match up.
      if(b2[0] != temp3[0] || b2[1] != temp3[1]) {
        return false;
      }

      return true;
    }
}
