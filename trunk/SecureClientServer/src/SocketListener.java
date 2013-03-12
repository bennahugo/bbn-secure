import java.net.InetAddress;

/**
 * Socket Event Handling Interface
 * @author Benjamin
 */
public interface SocketListener {
	/**
	 * The Event is called when data has been received
	 * @param clientAddress Address of the sender
	 * @param data Received data as a string (NEVER convert binary data to strings. Does not work. Use Base64 instead)
	 */
	public void onIncommingData(InetAddress clientAddress, int port, String data);
	/**
	 * On the event of an incoming connection the parent is notified with this handler 
	 * @param s a TCPSocket
	 */
	public void onIncommingConnection(TCPSocket s);
	
	public void onClientSecured(TCPSocket s);
}
