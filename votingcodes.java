import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;


public class Main {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
    	System.out.println("Computing your voting codes. Please wait.");
    	
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    	KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
    	g.initialize(ecSpec, new SecureRandom());
    	KeyPair pair = g.generateKeyPair();
    	
    	String filename = "voter.txt";
    	
    	/*
    	 * Compute x and xG 
    	 */
    	BigInteger x = ((ECPrivateKey) pair.getPrivate()).getD();
    	
    	ECPoint xG = ((ECPublicKey) pair.getPublic()).getQ();
    	
    	BigInteger _x = xG.getAffineXCoord().toBigInteger();
    	BigInteger _y = xG.getAffineYCoord().toBigInteger();
    	
    	/*
    	 * Compute v, w, r, d
    	 */
    	pair = g.generateKeyPair();
    	BigInteger v = ((ECPrivateKey) pair.getPrivate()).getD();
    	
    	pair = g.generateKeyPair();
    	BigInteger w = ((ECPrivateKey) pair.getPrivate()).getD();
    	
    	pair = g.generateKeyPair();
    	BigInteger r = ((ECPrivateKey) pair.getPrivate()).getD();
    	
    	pair = g.generateKeyPair();
    	BigInteger d = ((ECPrivateKey) pair.getPrivate()).getD();
    	
    	String toPrint = x.toString() + "," + _x + "," + _y + "," + v + "," + w + "," + r + "," + d;
    	
    	System.out.println("Voting codes computed. Saving to file " + filename);
		File outFile = new File (filename);
		FileWriter fWriter = new FileWriter (outFile);
		PrintWriter pWriter = new PrintWriter (fWriter);
		pWriter.println(toPrint);
		pWriter.close();
    }
}
