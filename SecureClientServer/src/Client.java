import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Date;

/**
 * Client program for Secure transmission (provides authentication using RSA and AES block encryption using 
 * Diffie Hellman key exchange)
 * @author benjamin
 */
public class Client implements SocketListener, Runnable{
	private TCPSocket sock;
	private NonBlockingReader rdr;
	private Thread thread;
	enum ClientState {CS_NOT_SPECIFIED_USER,CS_NOT_SPECIFIED_MODULUS,
		CS_NOT_SPECIFIED_EXPONENT,CS_SERVER_NOT_AUTHENTICATED,
		CS_SERVER_AUTHENTICATED,CS_HANDSHAKE_ACHIEVED}
	private ClientState myState = ClientState.CS_NOT_SPECIFIED_USER;
	private java.util.Date timeStamp;
	private BigInteger pkMod,pkExp;
	private RSAPrivateKeySpec pk;
	private String name;
	private CypherMachine cypher;
	private KeyringReader keyring;
	/**
	 * Default constructor for client program
	 */
	public Client(){	
		System.out.println("\n***********************************************");
		System.out.println("*                   Client                    *");
		System.out.println("***********************************************");
		//Try to connect
		InetAddress ip = null;
		try{
			ip = Inet4Address.getByAddress(ProtocolInfo.SERVER_ADDRESS);
		} catch (UnknownHostException e) {
			System.out.println("Could not resolve destination IP");
			e.printStackTrace();
			System.exit(1);
		}
		try {
			sock = new TCPSocket(this,ProtocolInfo.SERVER_PORT,ip);
		} catch (Exception e) {
			System.out.println("Could not establish socket. This normally happens if the server is not running.");
			e.printStackTrace();
			System.exit(1);
		}
		try{
			sock.waitTillSocketSecured();
		} catch (Exception e) {
			System.out.println("Socket could not be secured");
			System.exit(1);
		}
		//connected, so we can continue running
		//construct the non-blocking input reader
		rdr = new NonBlockingReader(Driver.s);
		try{
			cypher = new CypherMachine();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		//fetch the keyring
		try{
			keyring = new KeyringReader(ProtocolInfo.KEYRING_LOCATION);
		} catch (Exception e) {
			System.out.println("\nCould not read keyring. Missing file or corrupted");
			e.printStackTrace();
			System.exit(1);
		}
		//Done preliminaries, start thread
		thread = new Thread(this);
		thread.start();
		prompt();
		//Wait for the thread to finish and return to driver
		try {
			thread.join();
		} catch (InterruptedException e) {}
		sock.interrupt();
		rdr.interrupt();
	}
	@Override
	public void onIncommingData(InetAddress clientAddress, int port, String data) {
		synchronized(myState){
			switch (myState){
			case CS_SERVER_NOT_AUTHENTICATED:
				//check for an issue of distrust at this stage
				if (data.equals(ProtocolInfo.NO_TRUST)){
					System.out.println("AUTH: The server raised a distrust flag. Aborting at this stage.");
					System.exit(1);
				}
				//we have already sent our time stamp to the server so now we await a return in the form
				//encrypted myTimestamp ',' encrypted serverTimestamp (using RSA and my public key)
				byte[] recvClientStamp = null,recvServerStamp = null;
				try{
					recvClientStamp = cypher.RSAPriKeyDecrypt(Base64.decode(data.substring(0,data.indexOf(','))),
						pk);
					recvServerStamp = cypher.RSAPriKeyDecrypt(Base64.decode(data.substring(data.indexOf(',')+1)),
						pk);
				} catch (Exception e) {
					System.out.println("AUTH: Could not decrypt message using my private key. Server is not trustworthy. Aborting at this time.");
					System.exit(1);
				}
				//The message has been decrypted, but is it any good, if not ABORT the connection immediately
				if (CypherMachine.compareByteArrays(recvClientStamp, 
						ByteBuffer.allocate(8).putLong(timeStamp.getTime()).array())){
					try {
						System.out.println("\nAUTH: Server has authenticated itself (received timestamp matches)");
						sock.sendData(Base64.encodeBytes(cypher.RSAPriKeyEncrypt(recvServerStamp, pk)));
						myState = ClientState.CS_SERVER_AUTHENTICATED;
						System.out.println("\nAUTH: I've authenticated myself by sending the server's timestamp back");
						prompt();
					} catch (Exception e) {
						System.out.println("\nConnection has been lost. Could not send data. Please check server and try sending again.");
						System.exit(1);
					}
				} else {
					System.out.println("AUTH: Could not decrypt message using my private key. Server is not trustworthy. Aborting at this time.");
					System.exit(1);
				}
				break;
			case CS_SERVER_AUTHENTICATED:
				//Check for an issue of no trust:
				if (data.equals(ProtocolInfo.NO_TRUST)){
					System.out.println("AUTH: The server raised a distrust flag. Aborting at this stage.");
					System.exit(1);
				} else if (data.equals(ProtocolInfo.HANDSHAKE_ACK)){ //otherwise we await handshake confirmation
					myState = ClientState.CS_HANDSHAKE_ACHIEVED;
					System.out.println("AUTH: Handshake successfully achieved");
					prompt();
				}
				break;
			default:
				System.out.println("Server says: "+data);
				break;
			}
		}
	}
	/**
	 * Procedure to prompt the user with the correct message (based on state)
	 */
	private void prompt(){
		synchronized(myState){
			switch (myState){
			case CS_NOT_SPECIFIED_USER:
				System.out.print("\nPlease specify your user name\n>");
				break;
			case CS_NOT_SPECIFIED_MODULUS:
				System.out.print("\nPlease enter the modulus section of your private key\n>");
				break;
			case CS_NOT_SPECIFIED_EXPONENT:
				System.out.print("\nPlease enter the exponent section of your private key\n>");
				break;
			case CS_SERVER_NOT_AUTHENTICATED:
				System.out.print("\nWaiting for serverside authentication\n");
				break;
			case CS_SERVER_AUTHENTICATED:
				System.out.print("\nWaiting for handshake acknowledgement\n");
				break;
			case CS_HANDSHAKE_ACHIEVED:
				System.out.print("\nType 'SEND ' and your message to send.\nType 'X' to exit\n>");
				break;
			}
		}
	}
	/**
	 * Procedure for handling input received from the user (based on state)
	 * @param input
	 */
	private void handleInput(String input){ 
		synchronized(myState){
			switch (myState){
			case CS_NOT_SPECIFIED_USER:
				name = input;
				if (keyring.getKeys().containsKey(name))
					myState = ClientState.CS_NOT_SPECIFIED_MODULUS;
				else{
					System.out.println("\nYour user name could not be found on the keyring. Please try again.");
					System.exit(1);
				}
				prompt();
				break;
			case CS_NOT_SPECIFIED_MODULUS:
				try{
					pkMod = new BigInteger(input);
					myState = ClientState.CS_NOT_SPECIFIED_EXPONENT;
				} catch (NumberFormatException e){
					System.out.println("\nInvalid input. Specify a number please.");
				} finally {
					prompt();
				}
				break;
			case CS_NOT_SPECIFIED_EXPONENT:
				try{
					pkExp = new BigInteger(input);
					
					pk = new RSAPrivateKeySpec(pkMod, pkExp);
					byte[] cypherText = null , plaintext = null;
					//First check if the user entered the correct private key by encrypting and decrypting some arb string
					try{
						cypherText = cypher.RSAPubKeyEncrypt("7r@p d00R".getBytes(), keyring.getKeys().get(name));
					} catch (Exception e){
						System.out.println("Your key does not match RSA specifications. Please retry inputting your key.");
						System.exit(1);
					}
					try{
						plaintext = cypher.RSAPriKeyDecrypt(cypherText,pk);
					} catch (Exception e){
						System.out.println("Your key does not match RSA specifications. Please retry inputting your key.");
						System.exit(1);
					}
					//Check decrypted text
					if (CypherMachine.compareByteArrays("7r@p d00R".getBytes(),plaintext)){
						System.out.println("Access Granted");
					}
					else {
						System.out.println("Access Denied");
						System.exit(1);
					}
					//The user has entered the correct key combination (mod and exponent)
					myState = ClientState.CS_SERVER_NOT_AUTHENTICATED;
					//Start handshake by encrypting a timestamp with the server's public key
					timeStamp = new java.util.Date();
					try{
						sock.sendData(name+","+
								Base64.encodeBytes(cypher.RSAPubKeyEncrypt(
										ByteBuffer.allocate(8).putLong(timeStamp.getTime()).array(),
										keyring.getKeys().get("server"))));
						System.out.println("\nAUTH: I've generated a time stamp and sent it off to the server for authentication");
					} catch (Exception e) {
						System.out.println("\nConnection has been lost. Could not send data. Please check server and try sending again.");
						System.exit(1);
					}
				} catch (NumberFormatException e){
					System.out.println("\nInvalid input. Specify a number please.");
				} finally {
					prompt();
				}
				break;
			case CS_SERVER_NOT_AUTHENTICATED:
				System.out.println("\nCannot receive input at this time. Handshake not yet reached.");
				prompt();
				break;
			case CS_SERVER_AUTHENTICATED:
				System.out.println("\nCannot receive input at this time. Handshake not yet reached.");
				prompt();
				break;
			case CS_HANDSHAKE_ACHIEVED:
				//Now we can finally start sending text accross the network. It is secured by AES with an exchanged key
				if (input.equals("X"))
					thread.interrupt();
				else if (input.trim().startsWith("SEND ")){ 
					try {
						sock.sendData(input.trim().substring(5));
					} catch (Exception e) {
						System.out.println("\nConnection has been lost. Could not send data. Please check server and try sending again.");
						System.exit(1);
					}
					System.out.println("\nSuccess: Message sent");
					prompt();
				}
				else{
					System.out.println("\nWrong input. Try again.");
					prompt();
				}
				break;
			}
		}
	}
	@Override
	public void run() {
		while (!Thread.interrupted()){
			String input = rdr.getNextLine();
			if (input != null) handleInput(input);
			try{
				Thread.sleep(10);
			}
			catch (InterruptedException e){break;}
		}
	}
	@Override
	public void onIncommingConnection(TCPSocket s) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void onClientSecured(TCPSocket s) {
		// TODO Auto-generated method stub
		
	}
}
