import java.net.InetAddress;

/**
 * Socket Event Handling Interface
 * @author Benjamin
 */
public interface SocketListener {
	/**
	 * The Event is called when data has been received
	 * @param clientAddress Address of the sender
	 * @param data Received data as a string
	 */
	public void onIncommingData(InetAddress clientAddress, int port, String data);
	public void onIncommingConnection(TCPSocket s);
}
