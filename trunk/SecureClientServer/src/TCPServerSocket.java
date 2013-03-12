import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
/**
 * Basic thread-based TCP Server Socket
 * @author benjamin
 */
public class TCPServerSocket extends Thread {
	SocketListener ear;
	ServerSocket listensocket;
	HashMap<Integer,Socket> conns = new HashMap<Integer,Socket>();
	/**
	 * Default constructor for persistent TCP server socket (make sure you stop the socket once you dont need it anymore)
	 * 
	 * @param ear event handler class 
	 * @param port port to be bound to this listening socket
	 * @throws IOException
	 */
	public TCPServerSocket(SocketListener ear,int port) throws IOException{
		this.ear = ear;
		listensocket = new ServerSocket(port);
		this.start();
	}
	/**
	 * Disconnect a client from the network
	 * @param sock a client socket (as spawned by this socket)
	 */
	public void disconnect(TCPSocket sock){
		conns.remove(sock.hashCode());
	}
	/**
	 * Run method for the server thread (dont call this directly!)
	 */
	public void run()
	{
		while(!Thread.currentThread().isInterrupted())
		{
			try
			{		
				Socket connectionSocket = listensocket.accept(); //bind client to a separate thread
				conns.put(connectionSocket.hashCode(), connectionSocket);
				TCPSocket handlerThread = new TCPSocket(connectionSocket,ear,this);
				ear.onIncommingConnection(handlerThread); //NEW CONNECTION EVENT!!!
			}
			catch (Exception e) { e.printStackTrace(); }
		}
		try
		{
			this.listensocket.close(); //finally close the listener
		}
		catch (Exception e) { System.out.println("Could not close socket properly."); }
	}
}
