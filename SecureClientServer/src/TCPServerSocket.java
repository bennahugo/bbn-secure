import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

public class TCPServerSocket extends Thread {
	SocketListener ear;
	ServerSocket listensocket;
	HashMap<Integer,Socket> conns = new HashMap<Integer,Socket>();
	public TCPServerSocket(SocketListener ear,int port) throws IOException{
		this.ear = ear;
		listensocket = new ServerSocket(port);
		this.start();
	}
	public void disconnect(TCPSocket sock){
		conns.remove(sock.hashCode());
	}
	public void run()
	{
		while(!Thread.currentThread().isInterrupted())
		{
			try
			{		
				Socket connectionSocket = listensocket.accept();
				conns.put(connectionSocket.hashCode(), connectionSocket);
				TCPSocket handlerThread = new TCPSocket(connectionSocket,ear,this);
				ear.onIncommingConnection(handlerThread);
			}
			catch (Exception e) { e.printStackTrace(); }
		}
		try
		{
			this.listensocket.close();
		}
		catch (Exception e) { System.out.println("Could not close socket properly."); }
	}
}
