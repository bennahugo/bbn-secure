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
	public CypherMachine () throws NoSuchAlgorithmException, NoSuchPaddingException{
		rsa = Cipher.getInstance("RSA");
	}
	public byte[] RSAPubKeyEncrypt(byte[] clearText, RSAPublicKeySpec key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.ENCRYPT_MODE, keyFac.generatePublic(key));
		byte[] cypherText = rsa.doFinal(clearText);
		return cypherText;
	}
	public byte[] RSAPriKeyEncrypt(byte[] clearText, RSAPrivateKeySpec key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.ENCRYPT_MODE, keyFac.generatePrivate(key));
		byte[] cypherText = rsa.doFinal(clearText);
		return cypherText;
	}
	public byte[] RSAPubKeyDecrypt(byte[] cypherText, RSAPublicKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.DECRYPT_MODE, keyFac.generatePublic(key));
		byte[] clearText = rsa.doFinal(cypherText);
		return clearText;
	}
	public byte[] RSAPriKeyDecrypt(byte[] cypherText, RSAPrivateKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException{
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		rsa.init(Cipher.DECRYPT_MODE, keyFac.generatePrivate(key));
		byte[] clearText = rsa.doFinal(cypherText);
		return clearText;
	}
}
