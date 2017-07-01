pragma solidity ^0.4.10;

/**
 * @title ECCMath_noconflict
 *
 * Functions for working with integers, curve-points, etc.
 *
 * @author Andreas Olofsson (androlo1980@gmail.com)
 */
library ECCMath_noconflict {
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
        bit = bit;
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

library Secp256k1_noconflict {

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

        uint sInv = ECCMath_noconflict.invmod(rs[1], n);
        uint[3] memory u1G = _mul(mulmod(uint(message), sInv, n), [Gx, Gy]);
        uint[3] memory u2Q = _mul(mulmod(rs[0], sInv, n), Q);
        uint[3] memory P = _add(u1G, u2Q);

        if (P[2] == 0)
            return false;

        uint Px = ECCMath_noconflict.invmod(P[2], p); // need Px/Pz^2
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
        var y_ = ECCMath_noconflict.expmod(y2, (p + 1) / 4, p);
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
        
        dwPtr = dwPtr;

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

        INV[7] = ECCMath_noconflict.invmod(INV[6], p);             // a7inv
        INV[8] = INV[7];                                // aNinv (a7inv)

        INV[15] = mulmod(INV[5], INV[8], p);            // z7inv
        for(uint k = 6; k >= 2; k--) {                  // z6inv to z2inv
            INV[8] = mulmod(PREC[k + 1][2], INV[8], p);
            INV[8 + k] = mulmod(INV[k - 2], INV[8], p);
        }
        INV[9] = mulmod(PREC[2][2], INV[8], p);         // z1Inv
        for(k = 0; k < 7; k++) {
            ECCMath_noconflict.toZ1(PREC[k + 1], INV[k + 9], mulmod(INV[k + 9], INV[k + 9], p), p);
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

/*
 * @title LocalCrypto
 * Allow local calls to create and verify zkp.
 *  Author: Patrick McCorry
 */
contract LocalCrypto {

  // Modulus for public keys
  uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

  // Base point (generator) G
  uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

  // New  point (generator) Y
  uint constant Yx = 98038005178408974007512590727651089955354106077095278304532603697039577112780;
  uint constant Yy = 1801119347122147381158502909947365828020117721497557484744596940174906898953;

  // Modulus for private keys (sub-group)
  uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  uint[2] G;
  uint[2] Y;

  event Debug(uint x1, uint x2);

  // 2 round anonymous voting protocol
  // TODO: Right now due to gas limits there is an upper limit
  // on the number of participants that we can have voting...
  // I need to split the functions up... so if they cannot
  // finish their entire workload in 1 transaction, then
  // it does the maximum. This way we can chain transactions
  // to complete the job...
  function LocalCrypto() {
    G[0] = Gx;
    G[1] = Gy;

    Y[0] = Yx;
    Y[1] = Yy;
  }

  // Retrieve the commitment hash for a voters vote.
  function commitToVote(uint[4] params, uint[2] xG, uint[2] yG, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bytes32) {
    return sha3(msg.sender, params, xG, yG, y, a1, b1, a2, b2);
  }

  // vG (blinding value), xG (public key), x (what we are proving)
  // c = H(g, g^{v}, g^{x});
  // r = v - xz (mod p);
  // return(r,vG)
  function createZKP(uint x, uint v, uint[2] xG) returns (uint[4] res) {

      uint[2] memory G;
      G[0] = Gx;
      G[1] = Gy;

      if(!Secp256k1_noconflict.isPubKey(xG)) {
          throw; //Must be on the curve!
      }

      // Get g^{v}
      uint[3] memory vG = Secp256k1_noconflict._mul(v, G);

      // Convert to Affine Co-ordinates
      ECCMath_noconflict.toZ1(vG, pp);

      // Get c = H(g, g^{x}, g^{v});
      bytes32 b_c = sha256(msg.sender, Gx, Gy, xG, vG);
      uint c = uint(b_c);

      // Get 'r' the zkp
      uint xc = mulmod(x,c,nn);

      // v - xc
      uint r = submod(v,xc);

      res[0] = r;
      res[1] = vG[0];
      res[2] = vG[1];
      res[3] = vG[2];
      return;
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
      if(!Secp256k1_noconflict.isPubKey(xG) || !Secp256k1_noconflict.isPubKey(vG)) {
        return false; //Must be on the curve!
      }

      // Get c = H(g, g^{x}, g^{v});
      bytes32 b_c = sha256(msg.sender, Gx, Gy, xG, vG);
      uint c = uint(b_c);

      // Get g^{r}, and g^{xc}
      uint[3] memory rG = Secp256k1_noconflict._mul(r, G);
      uint[3] memory xcG = Secp256k1_noconflict._mul(c, xG);

      // Add both points together
      uint[3] memory rGxcG = Secp256k1_noconflict._add(rG,xcG);

      // Convert to Affine Co-ordinates
      ECCMath_noconflict.toZ1(rGxcG, pp);

      // Verify. Do they match?
      if(rGxcG[0] == vG[0] && rGxcG[1] == vG[1]) {
         return true;
      } else {
         return false;
      }
  }

  // random 'w', 'r1', 'd1'
  function create1outof2ZKPNoVote(uint[2] xG, uint[2] yG, uint w, uint r2, uint d2, uint x) returns (uint[10] res, uint[4] res2){
      uint[2] memory temp_affine1;
      uint[2] memory temp_affine2;

      // y = h^{x} * g
      uint[3] memory temp1 = Secp256k1_noconflict._mul(x,yG);
      ECCMath_noconflict.toZ1(temp1, pp);

      // Store y_x and y_y
      res[0] = temp1[0];
      res[1] = temp1[1];

      // a1 = g^{w}
      temp1 = Secp256k1_noconflict._mul(w,G);
      ECCMath_noconflict.toZ1(temp1, pp);

      // Store a1_x and a1_y
      res[2] = temp1[0];
      res[3] = temp1[1];

      // b1 = h^{w} (where h = g^{y})
      temp1 = Secp256k1_noconflict._mul(w, yG);
      ECCMath_noconflict.toZ1(temp1, pp);

      res[4] = temp1[0];
      res[5] = temp1[1];

      // a2 = g^{r2} * x^{d2}
      temp1 = Secp256k1_noconflict._mul(r2,G);
      temp1 = Secp256k1_noconflict._add(temp1, Secp256k1_noconflict._mul(d2,xG));
      ECCMath_noconflict.toZ1(temp1, pp);

      res[6] = temp1[0];
      res[7] = temp1[1];

      // Negate the 'y' co-ordinate of G
      temp_affine1[0] = G[0];
      temp_affine1[1] = pp - G[1];

      // We need the public key y in affine co-ordinates
      temp_affine2[0] = res[0];
      temp_affine2[1] = res[1];

      // We should end up with y^{d2} + g^{d2} .... (but we have the negation of g.. so y-g).
      temp1 = Secp256k1_noconflict._add(Secp256k1_noconflict._mul(d2,temp_affine2), Secp256k1_noconflict._mul(d2,temp_affine1));

      // Now... it is h^{r2} + temp2..
      temp1 = Secp256k1_noconflict._add(Secp256k1_noconflict._mul(r2,yG),temp1);

      // Convert to Affine Co-ordinates
      ECCMath_noconflict.toZ1(temp1, pp);

      res[8] = temp1[0];
      res[9] = temp1[1];

      // Get c = H(i, xG, Y, a1, b1, a2, b2);
      bytes32 b_c = sha256(msg.sender, xG, res);

      // d1 = c - d2 mod q
      temp1[0] = submod(uint(b_c),d2);

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

  // random 'w', 'r1', 'd1'
  // TODO: Make constant
  function create1outof2ZKPYesVote(uint[2] xG, uint[2] yG, uint w, uint r1, uint d1, uint x) returns (uint[10] res, uint[4] res2) {
      // y = h^{x} * g
      uint[3] memory temp1 = Secp256k1_noconflict._mul(x,yG);
      Secp256k1_noconflict._addMixedM(temp1,G);
      ECCMath_noconflict.toZ1(temp1, pp);
      res[0] = temp1[0];
      res[1] = temp1[1];

      // a1 = g^{r1} * x^{d1}
      temp1 = Secp256k1_noconflict._mul(r1,G);
      temp1 = Secp256k1_noconflict._add(temp1, Secp256k1_noconflict._mul(d1,xG));
      ECCMath_noconflict.toZ1(temp1, pp);
      res[2] = temp1[0];
      res[3] = temp1[1];

      // b1 = h^{r1} * y^{d1} (temp = affine 'y')
      temp1 = Secp256k1_noconflict._mul(r1,yG);

      // Setting temp to 'y'
      uint[2] memory temp;
      temp[0] = res[0];
      temp[1] = res[1];

      temp1= Secp256k1_noconflict._add(temp1, Secp256k1_noconflict._mul(d1, temp));
      ECCMath_noconflict.toZ1(temp1, pp);
      res[4] = temp1[0];
      res[5] = temp1[1];

      // a2 = g^{w}
      temp1 = Secp256k1_noconflict._mul(w,G);
      ECCMath_noconflict.toZ1(temp1, pp);

      res[6] = temp1[0];
      res[7] = temp1[1];

      // b2 = h^{w} (where h = g^{y})
      temp1 = Secp256k1_noconflict._mul(w, yG);
      ECCMath_noconflict.toZ1(temp1, pp);
      res[8] = temp1[0];
      res[9] = temp1[1];

      // Get c = H(id, xG, Y, a1, b1, a2, b2);
      // id is H(round, voter_index, voter_address, contract_address)...
      bytes32 b_c = sha256(msg.sender, xG, res);
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

  // We verify that the ZKP is of 0 or 1.
  function verify1outof2ZKP(uint[4] params, uint[2] xG, uint[2] yG, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bool) {
      uint[2] memory temp1;
      uint[3] memory temp2;
      uint[3] memory temp3;

      // Make sure we are only dealing with valid public keys!
      if(!Secp256k1_noconflict.isPubKey(xG) || !Secp256k1_noconflict.isPubKey(yG) || !Secp256k1_noconflict.isPubKey(y) || !Secp256k1_noconflict.isPubKey(a1) ||
         !Secp256k1_noconflict.isPubKey(b1) || !Secp256k1_noconflict.isPubKey(a2) || !Secp256k1_noconflict.isPubKey(b2)) {
         return false;
      }

      // Does c =? d1 + d2 (mod n)
      if(uint(sha256(msg.sender, xG, y, a1, b1, a2, b2)) != addmod(params[0],params[1],nn)) {
        return false;
      }

      // a1 =? g^{r1} * x^{d1}
      temp2 = Secp256k1_noconflict._mul(params[2], G);
      temp3 = Secp256k1_noconflict._add(temp2, Secp256k1_noconflict._mul(params[0], xG));
      ECCMath_noconflict.toZ1(temp3, pp);

      if(a1[0] != temp3[0] || a1[1] != temp3[1]) {
        return false;
      }

      //b1 =? h^{r1} * y^{d1} (temp = affine 'y')
      temp2 = Secp256k1_noconflict._mul(params[2],yG);
      temp3 = Secp256k1_noconflict._add(temp2, Secp256k1_noconflict._mul(params[0], y));
      ECCMath_noconflict.toZ1(temp3, pp);

      if(b1[0] != temp3[0] || b1[1] != temp3[1]) {
        return false;
      }

      //a2 =? g^{r2} * x^{d2}
      temp2 = Secp256k1_noconflict._mul(params[3],G);
      temp3 = Secp256k1_noconflict._add(temp2, Secp256k1_noconflict._mul(params[1], xG));
      ECCMath_noconflict.toZ1(temp3, pp);

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
      temp2 = Secp256k1_noconflict._addMixed(temp3,temp1);

      // Return to affine co-ordinates
      ECCMath_noconflict.toZ1(temp2, pp);
      temp1[0] = temp2[0];
      temp1[1] = temp2[1];

      // (y-g)^{d2}
      temp2 = Secp256k1_noconflict._mul(params[1],temp1);

      // Now... it is h^{r2} + temp2..
      temp3 = Secp256k1_noconflict._add(Secp256k1_noconflict._mul(params[3],yG),temp2);

      // Convert to Affine Co-ordinates
      ECCMath_noconflict.toZ1(temp3, pp);

      // Should all match up.
      if(b2[0] != temp3[0] || b2[1] != temp3[1]) {
        return false;
      }

      return true;
    }

    // Expects random factor 'r' and commitment 'b'. Generators are hard-coded into this contract.
    function createCommitment(uint r, uint b) returns (uint[2]){

      uint[3] memory bG = Secp256k1_noconflict._mul(b,G);

      uint[3] memory rY = Secp256k1_noconflict._mul(r,Y);

      uint[3] memory c = Secp256k1_noconflict._add(bG,rY);

      ECCMath_noconflict.toZ1(c, pp);

      uint[2] memory c_affine;
      c_affine[0] = c[0];
      c_affine[1] = c[1];

      // Sanity check that everything worked as expected.
      if(!Secp256k1_noconflict.isPubKey(c_affine)) {
          throw; //Must be on the curve!
      }

      return c_affine;
    }

    // We need to re-create the commitment and check that it matches c.
    function openCommitment(uint[2] c, uint r, uint b) returns (bool) {

      uint[2] memory c_computed = createCommitment(r,b);

      // Check that the commitments match...
      if(c[0] == c_computed[0] && c[1] == c_computed[1]) {
        return true;
      }

      return false;
    }

    // Equality of commitments...
    // 1. Compute t = r3*Y
    // 2. Compute h = H(ID, G, Y, C1, C2, t), where G,Y are generators, C1, C2 are both commitments, and t is random factor.
    // 3. Compute n = h*(r1,r2) + r3.
    // return t,n.
    function createEqualityProof(uint r1, uint r2, uint r3, uint[2] c1, uint[2] c2) returns (uint[2] t, uint n) {

      if(!Secp256k1_noconflict.isPubKey(c1)) {
          throw; //Must be on the curve!
      }

      if(!Secp256k1_noconflict.isPubKey(c2)) {
          throw; //Must be on the curve!
      }

      uint[3] memory r3Y = Secp256k1_noconflict._mul(r3,Y);
      ECCMath_noconflict.toZ1(r3Y, pp);

      t[0] = r3Y[0];
      t[1] = r3Y[1];

      // TODO: add msg.sender
      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t));

      uint subr1r2 = submod(r1, r2);
      uint modrh = mulmod(subr1r2,h,nn);
      n = addmod(modrh,r3,nn);
    }

    // We compute h*(c1-c2) + t
    function computeFirstHalfEquality(uint[2] c1, uint[2] c2, uint h, uint[2] t) returns (uint[2] left){

      uint[3] memory negative_c2;
      // Negate the 'y' co-ordinate of C2
      negative_c2[0] = c2[0];
      negative_c2[1] = pp - c2[1];
      negative_c2[2] = 1;

      // c1 - c2
      uint[3] memory added_commitments_jacob = Secp256k1_noconflict._addMixed(negative_c2,c1);

      // convert to affine points
      ECCMath_noconflict.toZ1(added_commitments_jacob,pp);
      uint[2] memory added_commitments;
      added_commitments[0] = added_commitments_jacob[0];
      added_commitments[1] = added_commitments_jacob[1];

      // h*(c1-c2) + t
      uint[3] memory left_jacob = Secp256k1_noconflict._addMixed(Secp256k1_noconflict._mul(h,added_commitments),t);
      ECCMath_noconflict.toZ1(left_jacob,pp);
      left[0] = left_jacob[0];
      left[1] = left_jacob[1];


    }

    // Verify equality proof of two pedersen commitments
    // 1. Compute h = H(ID, G, Y, C1, C2, t), where G,Y are generators, C1, C2 are both commitments, and t is random factor.
    // 2. Does nY == h*(c1-c2) + t
    function verifyEqualityProof(uint n,  uint[2] c1, uint[2] c2, uint[2] t) returns (bool) {
      if(!Secp256k1_noconflict.isPubKey(c1)) { throw; }
      if(!Secp256k1_noconflict.isPubKey(c2)) { throw; }
      if(!Secp256k1_noconflict.isPubKey(t)) { throw; }

      // Time to start trying to verify it... will be moved to another function
      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t));

      uint[2] memory left = computeFirstHalfEquality(c1,c2,h,t);

      // n * Y
      uint[3] memory right = Secp256k1_noconflict._mul(n,Y);

      ECCMath_noconflict.toZ1(right, pp);

      if(left[0] == right[0] && left[1] == right[1]) {
        return true;
      } else {
        return false;
      }
    }

    // Create inequality of commitments...
    // 1. t1 = r3*G, t2 = r4*Y
    // 2. Compute h = H(ID, G, Y, c1, c2, t1, t2), where G,Y generators, c1,c2 commitments, t1,t2 inequality proof
    // 3. n1 = h*(b1-b2) + r3, n2 = h*(r1-r2) + r4.
    // return random factors t1,t2 and proofs n1,n2.
    function createInequalityProof(uint b1, uint b2, uint r1, uint r2, uint r3, uint r4, uint[2] c1, uint[2] c2) returns (uint[2] t1, uint[2] t2, uint n1, uint n2) {

      if(!Secp256k1_noconflict.isPubKey(c1)) { throw; }
      if(!Secp256k1_noconflict.isPubKey(c2)) { throw; }

      // r3 * G
      uint[3] memory temp = Secp256k1_noconflict._mul(r3,G);
      ECCMath_noconflict.toZ1(temp, pp);
      t1[0] = temp[0];
      t1[1] = temp[1];

      // r4 * Y
      temp = Secp256k1_noconflict._mul(r4,Y);
      ECCMath_noconflict.toZ1(temp, pp);
      t2[0] = temp[0];
      t2[1] = temp[1];

      // TODO: add msg.sender
      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t1, t2));

      // h(b1-b2) + r3
      n1 = submod(b1,b2);
      uint helper = mulmod(n1,h,nn);
      n1 = addmod(helper,r3,nn);

      // h(r1-r2) + r4
      n2 = submod(r1,r2);
      helper = mulmod(n2,h,nn);
      n2 = addmod(helper,r4,nn);

    }

    // We are computing h(c1 - c2) + t2
    function computeSecondHalfInequality(uint[2] c1, uint[2] c2, uint[2] t2, uint h) returns (uint[3] right) {
      uint[3] memory negative_c2;
      // Negate the 'y' co-ordinate of C2
      negative_c2[0] = c2[0];
      negative_c2[1] = pp - c2[1];
      negative_c2[2] = 1;

      // c1 - c2
      uint[3] memory added_commitments_jacob = Secp256k1_noconflict._addMixed(negative_c2,c1);

      // convert to affine points
      ECCMath_noconflict.toZ1(added_commitments_jacob,pp);
      uint[2] memory added_commitments;
      added_commitments[0] = added_commitments_jacob[0];
      added_commitments[1] = added_commitments_jacob[1];

      // h(c1-c2)
      uint[3] memory h_mul_c1c2 = Secp256k1_noconflict._mul(h,added_commitments);

      // right hand side h(c1-c2) + t2
      right = Secp256k1_noconflict._addMixed(h_mul_c1c2,t2);
      ECCMath_noconflict.toZ1(right,pp);

    }

    // Verify inequality of commitments
    // 1. Compute h = H(ID, G, Y, c1, c2, t1, t2), where G,Y generators, c1,c2 commitments, t1,t2 inequality proof
    // 2. Verify n1G + n2Y = h*(c1-c2) + t1 + t2
    // 3. Verify n2Y != h*(c1-c2) + t2
    function verifyInequalityProof(uint[2] c1, uint[2] c2, uint[2] t1, uint[2] t2, uint n1, uint n2) returns (bool) {
      if(!Secp256k1_noconflict.isPubKey(c1)) { throw; }
      if(!Secp256k1_noconflict.isPubKey(c2)) { throw; }
      if(!Secp256k1_noconflict.isPubKey(t1)) { throw; }
      if(!Secp256k1_noconflict.isPubKey(t2)) { throw; }

      uint h = uint(sha256(msg.sender, G, Y, c1, c2, t1, t2));

      // h(c1 - c2) + t2
      uint[3] memory right = computeSecondHalfInequality(c1, c2, t2, h);

      // n2 * Y
      uint[3] memory n2Y = Secp256k1_noconflict._mul(n2,Y);
      ECCMath_noconflict.toZ1(n2Y,pp); // convert to affine

      if(n2Y[0] != right[0] && n2Y[1] != right[1]) {

        // h(c1 - c2) + t2 + t1
        uint[3] memory h_c1c2_t2_t1 = Secp256k1_noconflict._addMixed(right, t1);
        ECCMath_noconflict.toZ1(h_c1c2_t2_t1,pp); // convert to affine
        right[0] = h_c1c2_t2_t1[0];
        right[1] = h_c1c2_t2_t1[1];

        // n1G + n2Y
        uint[3] memory n1Gn2Y = Secp256k1_noconflict._add(Secp256k1_noconflict._mul(n1, G),n2Y);
        ECCMath_noconflict.toZ1(n1Gn2Y,pp); // convert to affine

        if(n1Gn2Y[0] == right[0] && n1Gn2Y[1] == right[1]) {
          return true;
        }
      }

      return false;
    }
}
