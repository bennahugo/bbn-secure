import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.Date;
/**
 * Secure server (provides mutual authentication and AES block encryption using Diffie Hellman key exchange) 
 * @author benjamin
 */
public class Server implements SocketListener,Runnable{
	private Thread thread;
	private TCPServerSocket sock;
	private NonBlockingReader rdr;
	private ArrayList<TCPSocket> unknownSockets; 
	private ArrayList<Pair<TCPSocket,String>>authenticatedSockets; 
	private ArrayList<Pair<TCPSocket,Pair<String,byte[]>>> unauthenticatedSockets;
	private KeyringReader keyring;
	private CypherMachine cypher;
	private RSAPrivateKeySpec pk;
	public Server(){
		try {
			sock = new TCPServerSocket(this,ProtocolInfo.SERVER_PORT);
		} catch (Exception e) {
			System.out.println("Could not establish socket. This normally happens when you try to run multiple servers.");
			e.printStackTrace();
			System.exit(1);
		}
		rdr = new NonBlockingReader(Driver.s);
		try{
			keyring = new KeyringReader(ProtocolInfo.KEYRING_LOCATION);
		} catch (Exception e) {
			System.out.println("\nCould not read keyring. Missing file or corrupted");
			e.printStackTrace();
			System.exit(1);
		}
		try{
			cypher = new CypherMachine();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		pk = new RSAPrivateKeySpec(
				new BigInteger("106552646548987747775799982470752321354613464888190003586735280912689621477051251518731532849179225407091383299774564288466375737201985922415443230079706656965365814775533860604483929010866271298722865213854049246766680001231445963555353946101665118756527053733522791467610722357913068363694616394809975353403"), 
				new BigInteger("106227478639107870003623044306140720819481818749708870780574683751047527327251745128391018230416757715841886425337911514343463868373074053021313369908872735808120018916948511985165473414468692763600577631646191044252687002911039909747897627609423694632590367687176641827882267809786761047246539003414789701601"));
		thread = new Thread(this);
		thread.start();
		unknownSockets = new ArrayList<TCPSocket>();
		unauthenticatedSockets = new ArrayList<Pair<TCPSocket,Pair<String,byte[]>>>(); 
		authenticatedSockets = new ArrayList<Pair<TCPSocket,String>>();
		System.out.println("\n***********************************************");
		System.out.println("*                   Server                    *");
		System.out.println("***********************************************");
		prompt();
		
		try {
			thread.join();
		} catch (InterruptedException e) {}
		sock.interrupt();
		rdr.interrupt();
	}
	@Override
	public synchronized void onIncommingData(InetAddress clientAddress, int port, String data) {
		for (int i = 0; i < unknownSockets.size(); ++i){
			TCPSocket s = unknownSockets.get(i);
			if (s.clientSocket.getInetAddress().toString().equals(clientAddress.toString())){
				try{
					String name = data.substring(0,data.indexOf(','));
					byte[] timestamp = cypher.RSAPriKeyDecrypt(
							Base64.decode(data.substring(data.indexOf(',')+1).getBytes()),pk);
					byte[] serverStamp = ByteBuffer.allocate(8).putLong(new Date().getTime()).array();
					System.out.println("\nAUTH: " + name + " has sent me a time stamp");
					System.out.println("\nAUTH: I'm authenticating by sending it back. I'm also sending along my own time stamp for this client");
					Pair<TCPSocket,Pair<String,byte[]>> pair = new Pair<TCPSocket,Pair<String,byte[]>>(s,
							new Pair<String,byte[]>(name,serverStamp));
					try {
						s.sendData(Base64.encodeBytes(cypher.RSAPubKeyEncrypt(timestamp,
								keyring.getKeys().get(name)))+','+Base64.encodeBytes(cypher.RSAPubKeyEncrypt(serverStamp,
										keyring.getKeys().get(name))));
						unauthenticatedSockets.add(pair);
					} catch (Exception e){
						System.out.println("\nLost connection to " + name + ". The party will have to retry later.");
					}
				} catch (Exception e){
					System.out.println("AUTH: Notion of mistrust raised for "+clientAddress.toString());
					try {s.sendData(ProtocolInfo.NO_TRUST); } catch (Exception exp) {};
				}
				finally {
					unknownSockets.remove(i);
					prompt();
				}
				return;
			}
		}
		for (int i = 0; i < unauthenticatedSockets.size(); ++i){
			Pair<TCPSocket,Pair<String,byte[]>> s = unauthenticatedSockets.get(i);
			if (s.getVal1().clientSocket.getInetAddress().toString().equals(clientAddress.toString())){
				try{
				byte[] decryption = cypher.RSAPubKeyDecrypt(Base64.decode(data), keyring.getKeys().get(s.getVal2().getVal1()));
				if (CypherMachine.compareByteArrays(decryption, s.getVal2().getVal2())){
					try {
						s.getVal1().sendData(ProtocolInfo.HANDSHAKE_ACK);
						System.out.println("\nAUTH: " + s.getVal2().getVal1() + " has authenticed. Handshake complete.");
						authenticatedSockets.add(new Pair<TCPSocket, String>(s.getVal1(), s.getVal2().getVal1()));
					} catch (Exception e){
						System.out.println("\nLost connection to " + s.getVal2().getVal1() + ". The party will have to retry later.");
					}
					finally{
						prompt();
					}
				} else throw new Exception("I do not trust this connection");
				} catch (Exception e) {
					System.out.println("AUTH: Notion of mistrust raised for "+clientAddress.toString());
					try {s.getVal1().sendData(ProtocolInfo.NO_TRUST); } catch (Exception exp) {};
				}
				unauthenticatedSockets.remove(i);
				return;
			}
		}
		prompt();
	}
	private void prompt(){
		System.out.println("\nType 'X' to exit");
		System.out.print(">");
	}
	@Override
	public void run() {
		while (!Thread.interrupted()){
			String input = rdr.getNextLine();
			if (input != null){
				if (input.equals("X"))
					thread.interrupt();
				else{
					System.out.println("\nInvalid Input");
					prompt();
				}
			}
			try{
				Thread.sleep(10);
			}
			catch (InterruptedException e){break;}
		
		}
	}
	@Override
	public synchronized void onIncommingConnection(TCPSocket s) {
		unknownSockets.add(s);
	}
}
