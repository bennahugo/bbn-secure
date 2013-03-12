import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class CypherMachine {
	private Cipher rsa;
	/**
	 * Default constructor for the CypherMachine
	 * @throws NoSuchAlgorithmException RSA or AES not available
	 * @throws NoSuchPaddingException Selected padding not available on the system
	 */
	public CypherMachine () throws NoSuchAlgorithmException, NoSuchPaddingException{
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
