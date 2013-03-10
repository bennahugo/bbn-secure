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

public class KeyGenerator {
	private static Scanner s = new Scanner(System.in);
	private static KeyringReader keyring;
	public static void main (String [] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, FileNotFoundException, IOException{
		System.out.println("********************************************************");
		System.out.println("RSA keyring generator");
		System.out.println("Warning: This tool is only for testing purposes only.");
		System.out.println("         It saves your private key in an insecure file.");
		System.out.println("********************************************************");
		File f = new File(ProtocolInfo.KEYRING_LOCATION);
		if (!f.exists()){
			f.createNewFile();
			System.out.println("Creating new keyring");
		}
		try{
			keyring = new KeyringReader(ProtocolInfo.KEYRING_LOCATION);
		} catch (Exception e) {
			System.out.println("Keyring is corrupted. Delete keys manually and try again.");
			e.printStackTrace();
			System.exit(1);
		}
		
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
	public static void saveToFile(String filename,RSAPublicKeySpec keyU,RSAPrivateKeySpec keyR) throws FileNotFoundException, IOException{
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
