import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Date;


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
	public Client(){	
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
		//connected, so we can continue running
		rdr = new NonBlockingReader(Driver.s);
		try{
			cypher = new CypherMachine();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		try{
			keyring = new KeyringReader(ProtocolInfo.KEYRING_LOCATION);
		} catch (Exception e) {
			System.out.println("\nCould not read keyring. Missing file or corrupted");
			e.printStackTrace();
			System.exit(1);
		}
		thread = new Thread(this);
		thread.start();
		
		System.out.println("\n***********************************************");
		System.out.println("*                   Client                    *");
		System.out.println("***********************************************");
		prompt();
		
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
				if (timeStamp.toString().equals(data.split(",")[0])){
					try {
						System.out.println("\nAUTH: Server has authenticated itself (received timestamp matches)");
						sock.sendData(data.split(",")[1]);
						myState = ClientState.CS_SERVER_AUTHENTICATED;
						System.out.println("\nAUTH: I've authenticated myself by sending the server's timestamp back");
						prompt();
					} catch (Exception e) {
						System.out.println("\nConnection has been lost. Could not send data. Please check server and try sending again.");
						System.exit(1);
					}
				}
				break;
			case CS_SERVER_AUTHENTICATED:
				if (data.equals(ProtocolInfo.HANDSHAKE_ACK)){
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
					try{
						cypherText = cypher.RSAPubKeyEncrypt("7r@p".getBytes(), keyring.getKeys().get(name));
					} catch (Exception e){
						System.out.println("Your key does not match RSA specifications. Please retry inputting your key.");
						System.exit(1);
					}
					try{
						plaintext = cypher.RSAPriKeyDecrypt(cypherText,pk);
					} catch (Exception e){
						e.printStackTrace();
						System.exit(1);
					}
					if (new String(plaintext).equals(new String("7r@p".getBytes()))){
						System.out.println("Matches YAY!");
					}
					else {
						System.out.println("Doesn't match FUCKOFF!");
					}
					myState = ClientState.CS_SERVER_NOT_AUTHENTICATED;
					timeStamp = new java.util.Date();
					try{
						sock.sendData(name+","+timeStamp.toString());
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
}
