import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;


public class Client implements SocketListener, Runnable{
	private TCPSocket _sock;
	private NonBlockingReader _rdr;
	private Thread _thread;
	enum ClientState {CS_NOT_SPECIFIED_USER,CS_NOT_SPECIFIED_MODULUS,
		CS_NOT_SPECIFIED_EXPONENT,CS_SERVER_NOT_AUTHENTICATED,
		CS_SERVER_AUTHENTICATED}
	private ClientState myState = ClientState.CS_NOT_SPECIFIED_USER;
	private java.util.Date timeStamp;
	private BigInteger pkMod,pkExp;
	private String name;
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
			_sock = new TCPSocket(this,ProtocolInfo.SERVER_PORT,ip);
		} catch (Exception e) {
			System.out.println("Could not establish socket. This normally happens if the server is not running.");
			e.printStackTrace();
			System.exit(1);
		}
		//connected, so we can continue running
		_rdr = new NonBlockingReader(Driver.s);
		_thread = new Thread(this);
		_thread.start();
		
		System.out.println("\n***********************************************");
		System.out.println("*                   Client                    *");
		System.out.println("***********************************************");
		prompt();
		
		try {
			_thread.join();
		} catch (InterruptedException e) {}
		_sock.interrupt();
		_rdr.interrupt();
	}
	@Override
	public void onIncommingData(InetAddress clientAddress, int port, String data) {
		synchronized(myState){
			switch (myState){
			case CS_SERVER_NOT_AUTHENTICATED:
				if (timeStamp.toString().equals(data.split(",")[0])){
					try {
						System.out.println("\nAUTH: Server has authenticated itself (received timestamp matches)");
						_sock.sendData(data.split(",")[1]);
						myState = ClientState.CS_SERVER_AUTHENTICATED;
						System.out.println("\nAUTH: I've authenticated myself by sending the server's timestamp back");
						prompt();
					} catch (Exception e) {
						System.out.println("\nConnection has been lost. Could not send data. Please check server and try sending again.");
						System.exit(1);
					}
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
				System.out.print("\nWaiting for handshake with server\n");
				break;
			case CS_SERVER_AUTHENTICATED:
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
				myState = ClientState.CS_NOT_SPECIFIED_MODULUS;
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
					myState = ClientState.CS_SERVER_NOT_AUTHENTICATED;
					timeStamp = new java.util.Date();
					try{
						_sock.sendData(name+","+timeStamp.toString());
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
				if (input.equals("X"))
					_thread.interrupt();
				else if (input.trim().startsWith("SEND ")){ 
					try {
						_sock.sendData(input.trim().substring(5));
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
			String input = _rdr.getNextLine();
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
