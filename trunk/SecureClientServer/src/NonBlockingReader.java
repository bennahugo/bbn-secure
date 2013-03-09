import java.util.ArrayList;
import java.util.Scanner;

/**
 * Non-blocking IO reader that can be interrupted in case the server/client state changes
 * using Producer-Consumer techniques 
 * @author Benjamin
 */
public class NonBlockingReader extends Thread{
	Scanner reader;
	ArrayList<String> inputBuffer;
	/**
	 * Constructor for reader
	 * @param s An instantiated scanner that is listening on an input stream
	 */
	public NonBlockingReader(Scanner s)
	{
		reader = s;
		inputBuffer = new ArrayList<String>();
		this.start();
	}
	/**
	 * Gets the next line of input
	 * @return a string if such a line exists otherwise null
	 */
	public String getNextLine()
	{
		synchronized(this)
		{
			if (inputBuffer.size() > 0)
			{
				String result = inputBuffer.get(0);
				inputBuffer.remove(0);
				return result;
			}
			else return null;
		}
	}
	/**
	 * Clears the input buffer (any input that has not been read will be lost)
	 */
	public void clearBuffer()
	{
		synchronized(this)
		{
			inputBuffer.clear();
		}
	}
	/**
	 * Method to put a string onto the list of inputs (at the last position)
	 * @param s String to add
	 */
	private void put(String s)
	{
		synchronized(this)
		{
			inputBuffer.add(s);
		}
	}
	public void run()
	{
		while (!Thread.currentThread().isInterrupted())
		{
			put(reader.nextLine());
		} 
	}
}
