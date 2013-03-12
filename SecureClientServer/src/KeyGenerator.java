import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
/**
 * RSA keyring generator for testing purposes
 * WARNING: INSECURE STORAGE OF PRIMARY KEY. 
 * 			IF YOU NEED TO USE IT FOR REAL LIFE 
 * 			PURPOSES THEN REMOVE THE STORAGE OF THE PRIVATE KEY. 
 * @author benjamin
 *
 */
public class KeyGenerator {
	private static Scanner s = new Scanner(System.in);
	private static KeyringReader keyring;
	/**
	 * Driver method for key generator (select 1 to add to keyring, 2 to recall keys (TESTING ONLY))
	 * @param args
	 */
	
	public static void main (String [] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, FileNotFoundException, IOException{
		System.out.println("********************************************************");
		System.out.println("RSA keyring generator");
		System.out.println("Warning: This tool is only for testing purposes only.");
		System.out.println("         It saves your private key in an insecure file.");
		System.out.println("********************************************************");
		//Create keyring file if not exists
		File f = new File(ProtocolInfo.KEYRING_LOCATION);
		if (!f.exists()){
			f.createNewFile();
			System.out.println("Creating new keyring");
		}
		//read the keyring
		try{
			keyring = new KeyringReader(ProtocolInfo.KEYRING_LOCATION);
		} catch (Exception e) {
			System.out.println("Keyring is corrupted. Delete keys manually and try again.");
			e.printStackTrace();
			System.exit(1);
		}
		//ask the user what to do
		String answerFinal = "";
		while (answerFinal.equals("")){
			System.out.print("1 to create key and add to keyring,\n2 to display previously generated private and public keys\n>");
			String answer = s.nextLine();
			if (answer.equals("1")){
				generate();
				answerFinal = answer;
			}

			else if (answer.equals("2")){
				loadOld();
				answerFinal = answer;
			}
			else
				System.out.println("Wrong input");
		}
		System.out.println("Done");
	}
	/**
	 * Procedure to generate public/private key set
	 * @throws NoSuchAlgorithmException is thrown when the RSA subsystem is missing
	 * @throws IOException In case the file was corrupted
	 */
	private static void generate() throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IOException{
		KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
		  RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(),
		  RSAPrivateKeySpec.class);
		System.out.println("\n***********************************************");
		System.out.println("Public Key");
		System.out.println("***********************************************");
		System.out.println("EXP: " + pub.getPublicExponent());
		System.out.println("MOD: " + pub.getModulus());
		System.out.println("\n***********************************************");
		System.out.println("Private Key");
		System.out.println("***********************************************");
		System.out.println("EXP: " + priv.getPrivateExponent());
		System.out.println("MOD: " + priv.getModulus());
		
		System.out.print("\n\nEnter your name:\n>");
		String ownerName = s.nextLine();
		saveToFile(ownerName,pub,priv);
		System.out.println("Saved file to "+ownerName+".keys");
	}
	/**
	 * Displays keys from a keypair file (VERY INSECURE --- KEEP THIS FILE SECURE YOURSELF)
	 * @throws FileNotFoundException
	 * @throws IOException File was corrupted
	 */
	private static void loadOld() throws FileNotFoundException, IOException{
		System.out.print("\n\nEnter your name:\n>");
		String ownerName = s.nextLine();
		Object[] arr = loadFromFile(ownerName);
		RSAPublicKeySpec pub = (RSAPublicKeySpec) arr[0];
		RSAPrivateKeySpec priv = (RSAPrivateKeySpec) arr[1];
		
		System.out.println("\n***********************************************");
		System.out.println("Public Key");
		System.out.println("***********************************************");
		System.out.println("EXP: " + pub.getPublicExponent());
		System.out.println("MOD: " + pub.getModulus());
		System.out.println("\n***********************************************");
		System.out.println("Private Key");
		System.out.println("***********************************************");
		System.out.println("EXP: " + priv.getPrivateExponent());
		System.out.println("MOD: " + priv.getModulus());
	}
	/**
	 * Saves the keypair to a .keys object file (VERY INSECURE), as well as adding it to a common keyring
	 * @param filename excluding extension
	 * @param keyU Public key
	 * @param keyR Private key
	 * @throws FileNotFoundException if keyring does not exist
	 * @throws IOException
	 */
	public static void saveToFile(String filename,RSAPublicKeySpec keyU,RSAPrivateKeySpec keyR) throws FileNotFoundException, IOException{
		//Save the keyset to an object file (VERY INSECURE)
		ObjectOutputStream oout = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream(filename+".keys")));
		try {
			oout.writeObject(keyR.getModulus());
			oout.writeObject(keyR.getPrivateExponent());
			oout.writeObject(keyU.getModulus());
			oout.writeObject(keyU.getPublicExponent());
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
		//saves the public key to the keyring
		oout = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream("common.keyring")));
		try {
			for (String n : keyring.getKeys().keySet()){
				oout.writeObject(n);
				RSAPublicKeySpec key = keyring.getKeys().get(n);
				oout.writeObject(key.getModulus());
				oout.writeObject(key.getPublicExponent());
			}
			oout.writeObject(filename);
			oout.writeObject(keyU.getModulus());
			oout.writeObject(keyU.getPublicExponent());
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}
	/**
	 * Loads keyset from a previously generated .keys object file
	 * @param filename (excluding extension)
	 * @return [public key, private key] as object array (just cast back) 
	 * @throws FileNotFoundException File does not exist
	 * @throws IOException File corrupted
	 */
	public static Object[] loadFromFile(String filename) throws FileNotFoundException, IOException{
		Object arr [] = new Object[2];
		ObjectInputStream oin = new ObjectInputStream(
				new BufferedInputStream(new FileInputStream(filename+".keys")));
		try {
			BigInteger privMod = (BigInteger) oin.readObject(),
					privExp = (BigInteger) oin.readObject(),
					pubMod = (BigInteger) oin.readObject(), 
					pubExp = (BigInteger) oin.readObject();
			RSAPrivateKeySpec priv = new RSAPrivateKeySpec(privMod, privExp);
			RSAPublicKeySpec publ = new RSAPublicKeySpec(pubMod, pubExp);
			arr[0] = publ;
			arr[1] = priv;
		} catch (Exception e) {
		    throw new IOException("Unexpected error", e);
		} finally {
		    oin.close();
		}
		return arr;
	}
}
