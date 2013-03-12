import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
/**
 * TCP Socket 
 * @author benjamin
 */
public class TCPSocket extends Thread{
	SocketListener ear;
	Socket clientSocket;
	TCPServerSocket parent;
	BigInteger DHShareMe = new BigInteger("500"); //TODO: get from nate's code
	BigInteger DHShareOther = null;
	BigInteger DHKey = new BigInteger("343249082103981203129031289741328974328941290312903890123890124328974328945"); //TODO: get from nate's code
	Cipher aesEncryptor;
	byte[] encryptorIV;
	byte[] encryptorSalt;
	SecretKey aesKey;
	Cipher aesDecryptor;
	byte[] decryptorIV;
	byte[] decryptorSalt;
	CountDownLatch securedSocket;
	/**
	 * Default constructor for TCP Socket (for general purpose clientside use)
	 * @param ear listener
	 * @param port server's port number
	 * @param ip server's IP address
	 * @throws Exception if connection is not possible
	 */
	public TCPSocket(SocketListener ear, int port, InetAddress ip) throws Exception
	{
		securedSocket = new CountDownLatch(1);
		this.ear = ear;
		clientSocket = new Socket(ip,port);
		try{
			System.out.println("\nDH: Sharing generator with the other party");
			sendData(DHShareMe.toString());
		} catch (Exception e){
			parent.disconnect(this);
		}
		this.start();
	}
	public void waitTillSocketSecured() throws InterruptedException{
		securedSocket.await();
	}
	/**
	 * Constructor to be used by a server socket (for a thread-per-client architecture - persistent TCP) 
	 * @param someSocket
	 * @param ear event handler class
	 * @param parent parent server socket 
	 */
	TCPSocket(Socket someSocket, SocketListener ear, TCPServerSocket parent){
		assert(parent != null);
		securedSocket = new CountDownLatch(1);
		clientSocket = someSocket;
		this.ear = ear;
		this.parent = parent;
		try{
			System.out.println("\nDH: Sharing generator with the other party");
			sendData(DHShareMe.toString());
		} catch (Exception e){
			parent.disconnect(this);
		}
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
			String sendText = Base64.encodeBytes(aesDecryptor != null ? CypherMachine.AESEncrypt(data.getBytes(), aesKey, aesEncryptor) : data.getBytes());
			DataOutputStream outToParty = new DataOutputStream(clientSocket.getOutputStream());
			outToParty.writeBytes(sendText + '\n');
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
						if (DHShareOther == null){							
							DHShareOther = new BigInteger(Base64.decode(line));
							System.out.println("\nDH: Receiving generator from the other party");
							//TODO: COMPUTE NEGOTIATED SECRET KEY
							System.out.println("\nDH: Negotiated, private session key is "+DHKey.toString());
							System.out.println("\nCONF: Setting up AES encryptor on my side");
							encryptorSalt = CypherMachine.generateSalt();
							Object[] out = CypherMachine.instantiateAESCypher(encryptorSalt, DHKey.toString(), null);
							aesEncryptor = (Cipher) out[0];
							aesKey = (SecretKey) out[1];
							encryptorIV = (byte[]) out[2];
							System.out.println("\nCONF: Sending salt and AES IV to other party");
							this.sendData(Base64.encodeBytes(encryptorSalt)+","+Base64.encodeBytes(encryptorIV));
						} else if (aesDecryptor == null){
							System.out.println("\nCONF: Received decryptor's salt and AES IV from other party");
							line = new String(Base64.decode(line));
							decryptorSalt = Base64.decode(line.substring(0,line.indexOf(',')));
							decryptorIV = Base64.decode(line.substring(line.indexOf(',')+1));
							Object[] out = CypherMachine.instantiateAESCypher(decryptorSalt, DHKey.toString(), decryptorIV);
							aesDecryptor = (Cipher) out[0];
							System.out.println("\nCONF: AES encryptor and decryptor ready. Session socket secured");
							securedSocket.countDown();
							ear.onClientSecured(this);
						}
						else {
							ear.onIncommingData(clientSocket.getInetAddress(), 
								clientSocket.getPort(), new String(CypherMachine.AESDecrypt(Base64.decode(line), aesKey, decryptorIV, aesDecryptor)));
						}
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
