//Example Implementation of Diffie-Hellman, client server
//Bob = Server + Alice = Client
//Nathan Floor
//FLRNAT001

public class runner {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			DiffieHellman DH_alice = new DiffieHellman(0,true);
			DiffieHellman DH_bob = new DiffieHellman(0,true);
			
			//Alice initiates process
			byte[] alicePubKey = DH_alice.getInitialPublicKey();
			
			//Bob responds + computes (same) shared key
			byte[] bobPubKey = DH_bob.receivePublicKey(alicePubKey);
			
			//Alice computes shared key, using bob's pubkey
			DH_alice.computeInitialSharedKey(bobPubKey);		
		} catch (Exception e) {
			System.err.println("Error: " + e);
			System.exit(1);
		}
		
		System.out.println("Done.");
	}

}
