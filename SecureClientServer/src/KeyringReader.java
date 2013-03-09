import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;


public class KeyringReader {
	private HashMap<String,RSAPublicKeySpec> keys;
	
	public KeyringReader(String filename) throws FileNotFoundException, IOException{
		keys = new HashMap<String,RSAPublicKeySpec>();
		ObjectInputStream oin = new ObjectInputStream(
				new BufferedInputStream(new FileInputStream(filename)));
		try {
			while (oin.available() > 0){
				String name = (String) oin.readObject();
				BigInteger pubMod = (BigInteger) oin.readObject(), 
						pubExp = (BigInteger) oin.readObject();
				RSAPublicKeySpec publ = new RSAPublicKeySpec(pubMod, pubExp);
				keys.put(name, publ);
			}
		} catch (Exception e) {
		    throw new IOException("Unexpected error", e);
		} finally {
		    oin.close();
		}
		
	}
}