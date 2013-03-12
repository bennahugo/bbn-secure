import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
/**
 * TCP Socket 
 * @author benjamin
 */
public class TCPSocket extends Thread{
	SocketListener ear;
	Socket clientSocket;
	TCPServerSocket parent;
	/**
	 * Default constructor for TCP Socket (for general purpose clientside use)
	 * @param ear listener
	 * @param port server's port number
	 * @param ip server's IP address
	 * @throws Exception if connection is not possible
	 */
	public TCPSocket(SocketListener ear, int port, InetAddress ip) throws Exception
	{
		this.ear = ear;
		clientSocket = new Socket(ip,port);
		
		this.start();
	}
	/**
	 * Constructor to be used by a server socket (for a thread-per-client architecture - persistent TCP) 
	 * @param someSocket
	 * @param ear event handler class
	 * @param parent parent server socket 
	 */
	TCPSocket(Socket someSocket, SocketListener ear, TCPServerSocket parent){
		assert(parent != null);
		clientSocket = someSocket;
		this.ear = ear;
		this.parent = parent;
		this.start();
	}
	/**
	 * Sends the string of data to the destination
	 * @param data data to send as a string
	 * @throws Exception if the data could not be sent
	 */
	public void sendData(String data) throws Exception
	{
		try
		{
			String sendText = Base64.encodeBytes(data.getBytes());
			DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
			outToServer.writeBytes(sendText + '\n');
		} catch (Exception e) 
		{ 
			throw new Exception("Connection timed out");
		}
	}
	/**
	 * Run method for the client thread (dont call this directly!)
	 */
	@Override
	public void run(){
		while(!Thread.currentThread().isInterrupted())
		{
			try
			{
				InputStream s = clientSocket.getInputStream();
				if (s != null){
					BufferedReader inFromClient =
							new BufferedReader(new InputStreamReader(s));
					
					String line = inFromClient.readLine();
					while (line != null)
					{
						ear.onIncommingData(clientSocket.getInetAddress(), 
								clientSocket.getPort(), new String(Base64.decode(line)));
						line = inFromClient.readLine();
					}
				}
			}
			catch (Exception e) { e.printStackTrace(); }
		}
		try
		{
			this.clientSocket.close();
			if (parent != null) parent.disconnect(this);
		}
		catch (Exception e) { System.out.println("Could not close socket properly."); }
	}
}
