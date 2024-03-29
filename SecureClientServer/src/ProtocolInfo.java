/**
 * Protocol information class
 * Contains all the control information necessary for client server communication
 * @author benjamin
 */
public class ProtocolInfo {
	public static final int SERVER_PORT = 8925;
	public static final byte[] SERVER_ADDRESS = {127,0,0,1};
	public static final String HANDSHAKE_ACK = "$$$ACK_HANDSHAKE$$$";
	public static final String NO_TRUST = "$$$NO_TRUST$$$";
	public static final String KEYRING_LOCATION = "common.keyring";
}
