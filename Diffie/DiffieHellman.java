//Diffie-Hellman implementation
//It must be noted that I have used the code from this website:
//But have cannibalized it for a client server situation.
//in this case, alice is the agent with whom we are trying to establish a shared key.

//Nathan Floor
//FLRNAT001

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;


public class DiffieHellman {
	//private instance variables
	private DHParameterSpec dhSkipParamSpec;
	private KeyAgreement keyAgree;
	private X509EncodedKeySpec x509KeySpec;
	private KeyPairGenerator KpairGen;
	private boolean debug = false;

	/* can instantiate with pre-generated parameters or for freshness, you can generate a new set. 
	 * Pass in the integer '1' to generate new parameters, and '0' to use pre-generated ones.
	 * You can specify a debug option to see console feedback to make sure the system is working.
	 */
	public DiffieHellman(int param, boolean d) throws Exception{	
		debug = d;
		if (param == 1) {
			// Some central authority creates new DH parameters
			if(debug)
				System.out.println("Creating Diffie-Hellman parameters (takes VERY long) ...");
			AlgorithmParameterGenerator paramGen =
					AlgorithmParameterGenerator.getInstance("DH");
			paramGen.init(512);
			AlgorithmParameters params = paramGen.generateParameters();
			dhSkipParamSpec =
					(DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
		} else {
			// use some pre-generated, default DH parameters
			if(debug)
				System.out.println("Using SKIP Diffie-Hellman parameters");
			dhSkipParamSpec = new DHParameterSpec(skip1024Modulus, skip1024Base);
		}		
	}
	
	/*
	 * returns public to start DH process
	 * creates own DH key pair, using the DH parameters
	 * TODO - 1
	 */
	public byte[] getInitialPublicKey() throws Exception{		
		if(debug)
			System.out.println("Generate DH keypair ...");
		KpairGen = KeyPairGenerator.getInstance("DH");
		KpairGen.initialize(dhSkipParamSpec);
		KeyPair keyPair = KpairGen.generateKeyPair();

		// creates and initializes DH KeyAgreement object
		if(debug)
			System.out.println("Initialization ...");
		keyAgree = KeyAgreement.getInstance("DH");
		keyAgree.init(keyPair.getPrivate());

		// encodes her public key, and sends it.
		byte[] pubKeyEnc = keyPair.getPublic().getEncoded();		
		
		return pubKeyEnc;
	}
	
	/*
	 * Received Alice's public key in encoded format.
	 * Instantiates a DH public key from the encoded key material.
	 * TODO - 2
	 */
	public byte[] receivePublicKey(byte[] publicKey) throws Exception{		
		KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
		x509KeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

		/*
		 * Gets the DH parameters associated with Alice's public key. 
		 * Must use the same parameters when generating own key pair.
		 */
		DHParameterSpec dhParamSpec = ((DHPublicKey) alicePubKey).getParams();

		//creates own DH key pair
		if(debug)
			System.out.println("Generate DH keypair ...");
		KpairGen = KeyPairGenerator.getInstance("DH");
		KpairGen.initialize(dhParamSpec);
		KeyPair keyPair = KpairGen.generateKeyPair();

		//creates and initializes DH KeyAgreement object
		if(debug)
			System.out.println("Initialization ...");
		keyAgree = KeyAgreement.getInstance("DH");
		keyAgree.init(keyPair.getPrivate());

		// encodes public key, and sends it over to Alice.
		byte[] pubKeyEnc = keyPair.getPublic().getEncoded();
		
		if(debug)
			System.out.println("Execute PHASE1 ...");
		keyAgree.doPhase(alicePubKey, true);
		
		byte[] sharedSecret =  keyAgree.generateSecret();
//		int bobLen = keyAgree.generateSecret(sharedSecret, 0);
		if(debug)
			System.out.println("Shared secret: " + toHexString(sharedSecret));
		
		return pubKeyEnc;
	}

	/*
	 * Use Alice's public key for the first (and only) phase
	 * of the DH protocol.
	 * Before need to instantiate a DH public key
	 * from Alice's encoded key material.
	 * TODO - 1
	 */
	public void computeInitialSharedKey(byte[] alicePubKey) throws Exception{
		KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
		x509KeySpec = new X509EncodedKeySpec(alicePubKey);
		PublicKey publicKey = aliceKeyFac.generatePublic(x509KeySpec);
		if(debug)
			System.out.println("Execute PHASE1 ...");
		keyAgree.doPhase(publicKey, true);
		
		/*
		 * At this stage, have completed the DH key agreement protocol.
		 * Both generate the (same) shared secret.
		 */
		byte[] sharedSecret = keyAgree.generateSecret();
		if(debug)
			System.out.println("Shared secret: " + toHexString(sharedSecret));
	}
	
	/*
	 * Converts a byte to hex digit and writes to the supplied buffer
	 * TODO - comment out for security reasons, when actually used
	 */
	private void byte2hex(byte b, StringBuffer buf) {
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
				'9', 'A', 'B', 'C', 'D', 'E', 'F' };
		int high = ((b & 0xf0) >> 4);
		int low = (b & 0x0f);
		buf.append(hexChars[high]);
		buf.append(hexChars[low]);
	}
	
	/*
	 * Converts a byte array to hex string
	 * TODO - comment out for security reasons, when actually used
	 */
	private String toHexString(byte[] block) {
		StringBuffer buf = new StringBuffer();

		int len = block.length;

		for (int i = 0; i < len; i++) {
			byte2hex(block[i], buf);
			if (i < len - 1) {
				buf.append(":");
			}
		}
		return buf.toString();
	}

	// The 1024 bit Diffie-Hellman modulus values used by SKIP
	private static final byte skip1024ModulusBytes[] = {
		(byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
		(byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
		(byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
		(byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
		(byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
		(byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
		(byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
		(byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
		(byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
		(byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
		(byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
		(byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
		(byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
		(byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
		(byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
		(byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
		(byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
		(byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
		(byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
		(byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
		(byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
		(byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
		(byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
		(byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
		(byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
		(byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
		(byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
		(byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
		(byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
		(byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
		(byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
		(byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
	};


	// The SKIP 1024 bit modulus
	private static final BigInteger skip1024Modulus =
			new BigInteger(1, skip1024ModulusBytes);

	// The base used with the SKIP 1024 bit modulus
	private static final BigInteger skip1024Base = BigInteger.valueOf(2);
}
