import java.util.Scanner;
/**
 * Driver class for application layer security (key exchange and authentication)
 * Network and internetwork Security
 * @author benjamin
 */
public class Driver {
	static Scanner s = null;
	public static void main (String [] args){
		s = new Scanner(System.in);
		
		System.out.println("***********************************************");
		System.out.println("*      Secure Client Server Transmission      *");
		System.out.println("***********************************************");
		int option = -1;
		while (option < 0){
			System.out.println("Choose an option:");
			System.out.println("1. Start client");
			System.out.println("2. Start server");
			System.out.println("X. Exit");
			System.out.print(">");
			String nextln = s.nextLine();
			if (nextln.equals("1")){
				option = 1;
				Client client = new Client(); // this thread will join up with the main thread when the client quits
			}
			else if (nextln.equals("2")){
				option = 2;
				Server server = new Server(); // this thread will join up with the main thread when the server quits
			}
			else if (nextln.equals("X")){
				option = 3;
			}
			else System.out.println("\nWrong input. Try again");
		}
		System.out.println("!!!Good Bye!!!");
		System.exit(0);
	}
}
