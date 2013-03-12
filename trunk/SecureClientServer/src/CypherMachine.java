import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class CypherMachine {
	private Cipher rsa;
	/**
	 * Default constructor for the CypherMachine
	 * @throws NoSuchAlgorithmException RSA not available
	 * @throws NoSuchPaddingException Selected padding not available on the system
	 * @throws InvalidKeySpecException  
	 */
	public CypherMachine () throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidParameterSpecException{
		rsa = Cipher.getInstance("RSA");
	}
	/**
	 * Method to encrypt using a public key (sign data)
	 * @param clearText clear text
	 * @param key public key
	 * @return cypher text
	 * @throws InvalidKeyException Provided key does not match specifications
	 * @throws NoSuchAlgorithmException RSA not available
	 * @throws InvalidKeySpecException Provided key does not match specifications
	 * @throws IllegalBlockSizeException Input block is more than 128 bytes long
	 * @throws BadPaddingException Padding system does not exist on this system
	 */
	public byte[] RSAPubKeyEncrypt(byte[] clearText, RSAPublicKeySpec key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.ENCRYPT_MODE, keyFac.generatePublic(key));
		byte[] cypherText = rsa.doFinal(clearText);
		return cypherText;
	}
	/**
	 * Method to encrypt using a private key (regular data encryption using RSA)
	 * @param clearText clear text
	 * @param key private key
	 * @return cypher text
	 * @throws InvalidKeyException Provided key does not match specifications
	 * @throws NoSuchAlgorithmException RSA not available
	 * @throws InvalidKeySpecException Provided key does not match specifications
	 * @throws IllegalBlockSizeException Input block is more than 128 bytes long
	 * @throws BadPaddingException Padding system does not exist on this system
	 */
	public byte[] RSAPriKeyEncrypt(byte[] clearText, RSAPrivateKeySpec key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.ENCRYPT_MODE, keyFac.generatePrivate(key));
		byte[] cypherText = rsa.doFinal(clearText);
		return cypherText;
	}
	/**
	 * Method to decrypt using a public key (regular data encryption using RSA)
	 * @param cypherText Input cypher text
	 * @param key public key spec
	 * @return plain text as byte array
	 * @throws NoSuchAlgorithmException RSA not available
	 * @throws InvalidKeyException Provided key does not match specifications
	 * @throws InvalidKeySpecException Provided key does not match specifications
	 * @throws IllegalBlockSizeException block should not be longer than 128 bits
	 * @throws BadPaddingException padding scheme not found
	 */
	public byte[] RSAPubKeyDecrypt(byte[] cypherText, RSAPublicKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.DECRYPT_MODE, keyFac.generatePublic(key));
		byte[] clearText = rsa.doFinal(cypherText);
		return clearText;
	}
	/**
	 * Method to decrypt using a private key (data signing)
	 * @param cypherText Input cypher text
	 * @param key private key spec
	 * @return plain text as byte array
	 * @throws NoSuchAlgorithmException RSA not available
	 * @throws InvalidKeyException Provided key does not match specifications
	 * @throws InvalidKeySpecException Provided key does not match specifications
	 * @throws IllegalBlockSizeException block should not be longer than 128 bits
	 * @throws BadPaddingException padding scheme not found
	 */
	public byte[] RSAPriKeyDecrypt(byte[] cypherText, RSAPrivateKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.DECRYPT_MODE, keyFac.generatePrivate(key));
		byte[] clearText = rsa.doFinal(cypherText);
		return clearText;
	}
	public static byte[]AESEncrypt(byte[] plainText,SecretKey aesKey, Cipher aes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException{
		byte[] cyphertext = aes.doFinal(plainText);
		return cyphertext;
	}
	public static byte[] AESDecrypt(byte[] cypherText,SecretKey aesKey,byte[] iv, Cipher aes) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		byte[] clearText = aes.doFinal(cypherText);
		return clearText;
	}
	public static Object[] instantiateAESCypher(byte [] salt, String password, byte[] IV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidParameterSpecException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException{
		Object[] collection = new Object[3];
		//Generate the key
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt , 65536, 128);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");
		//Construct the cipher
		Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
		if (IV == null){
			aes.init(Cipher.ENCRYPT_MODE, aesKey);
			AlgorithmParameters params = aes.getParameters();
			IV = params.getParameterSpec(IvParameterSpec.class).getIV();
		} else {
			aes.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(IV));
		}
		//return aes, aes key and IV
		collection[0] = aes;
		collection[1] = aesKey;
		collection[2] = IV;
		return collection;
	}
	public static byte[] generateSalt(){
		byte [] mSalt = new byte [8];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes (mSalt);
        return mSalt;
	}
	/**
	 * Compare byte arrays 
	 * @param arr1 input array 1
	 * @param arr2 input array 2
	 * @return true if and only if arr1 matches arr2 and equal length
	 */
	public static boolean compareByteArrays(byte[] arr1, byte[] arr2){
		if (arr1.length != arr2.length) return false;
		for (int i = 0; i < arr1.length; ++i)
			if (arr1[i] != arr2[i])
				return false;
		return true;
	}
}
