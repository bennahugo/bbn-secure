import java.math.BigInteger;
import java.util.HashMap;


public class KeyringReader {
	private HashMap<String,Pair<BigInteger,BigInteger>> keys;
	
	public KeyringReader(String filename){
		keys = new HashMap<String,Pair<BigInteger,BigInteger>>();
	}
}
