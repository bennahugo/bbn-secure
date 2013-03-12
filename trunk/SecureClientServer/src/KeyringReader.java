import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;

/**
 * Keyring file reader
 * @author benjamin
 */
public class KeyringReader {
	private final HashMap<String,RSAPublicKeySpec> keys;
	/**
	 * gets a hash map of public keys (based on person's name) 
	 * @return hash map of keys
	 */
	public HashMap<String, RSAPublicKeySpec> getKeys() {
		return keys;
	}
	/**
	 * Default constructor for keyring reader
	 * Keyring object file is in the format name, public modulus, private modulus
	 * @param filename filename of keyring
	 * @throws FileNotFoundException iff keyring object file is not found
	 * @throws IOException iff keyring object file is corrupted
	 */
	public KeyringReader(String filename) throws FileNotFoundException, IOException{
		keys = new HashMap<String,RSAPublicKeySpec>();
		ObjectInputStream oin = null;
		try{
			oin = new ObjectInputStream(
				new BufferedInputStream(new FileInputStream(filename)));
		} catch (EOFException e) { return; }
		try {
			while (true){
				try{
				String name = (String) oin.readObject();
				BigInteger pubMod = (BigInteger) oin.readObject(), 
						pubExp = (BigInteger) oin.readObject();
				RSAPublicKeySpec publ = new RSAPublicKeySpec(pubMod, pubExp);
				keys.put(name, publ);
				} catch (EOFException e) { break; }
			} 
		} catch (Exception e) {
		    throw new IOException("Unexpected error", e);
		} finally {
		    oin.close();
		}
	}
	
}
