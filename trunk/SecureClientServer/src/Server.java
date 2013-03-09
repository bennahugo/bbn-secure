import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Date;
public class Server implements SocketListener,Runnable{
	Thread _thread;
	TCPServerSocket _sock;
	NonBlockingReader _rdr;
	ArrayList<TCPSocket> unknownSockets; 
	ArrayList<Pair<TCPSocket,String>>authenticatedSockets; 
	ArrayList<Pair<TCPSocket,Pair<String,String>>> unauthenticatedSockets; 
	public Server(){
		try {
			_sock = new TCPServerSocket(this,ProtocolInfo.SERVER_PORT);
		} catch (Exception e) {
			System.out.println("Could not establish socket. This normally happens when you try to run multiple servers.");
			e.printStackTrace();
			System.exit(1);
		}
		_rdr = new NonBlockingReader(Driver.s);
		_thread = new Thread(this);
		_thread.start();
		unknownSockets = new ArrayList<TCPSocket>();
		unauthenticatedSockets = new ArrayList<Pair<TCPSocket,Pair<String,String>>>(); 
		authenticatedSockets = new ArrayList<Pair<TCPSocket,String>>();
		System.out.println("\n***********************************************");
		System.out.println("*                   Server                    *");
		System.out.println("***********************************************");
		prompt();
		
		try {
			_thread.join();
		} catch (InterruptedException e) {}
		_sock.interrupt();
		_rdr.interrupt();
	}
	@Override
	public synchronized void onIncommingData(InetAddress clientAddress, int port, String data) {
		for (int i = 0; i < unknownSockets.size(); ++i){
			TCPSocket s = unknownSockets.get(i);
			if (s.clientSocket.getInetAddress().toString().equals(clientAddress.toString())){
				String name = data.split(",")[0];
				String timestamp = data.split(",")[1];	
				String serverStamp = (new Date()).toString();
				System.out.println("\nAUTH: " + name + " has sent me a time stamp");
				System.out.println("\nAUTH: I'm authenticating by sending it back. I'm also sending along my own time stamp for this client");
				Pair<TCPSocket,Pair<String,String>> pair = new Pair<TCPSocket,Pair<String,String>>(s,new Pair(name,serverStamp));
				try {
					s.sendData(timestamp+","+serverStamp);
					unauthenticatedSockets.add(pair);
				} catch (Exception e){
					System.out.println("\nLost connection to " + name + ". The party will have to retry later.");
				}
				finally {
					unknownSockets.remove(i);
				}
				return;
			}
		}
		for (int i = 0; i < unauthenticatedSockets.size(); ++i){
			Pair<TCPSocket,Pair<String,String>> s = unauthenticatedSockets.get(i);
			if (s.getVal1().clientSocket.getInetAddress().toString().equals(clientAddress.toString())){
				if (s.getVal2().getVal2().equals(data)){
					System.out.println("\nAUTH: " + s.getVal2().getVal1() + " has authenticed. Handshake complete.");
					authenticatedSockets.add(new Pair<TCPSocket, String>(s.getVal1(), s.getVal2().getVal1()));
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
			String input = _rdr.getNextLine();
			if (input != null){
				if (input.equals("X"))
					_thread.interrupt();
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
