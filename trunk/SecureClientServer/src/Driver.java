import java.util.Scanner;
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
				Client client = new Client();
			}
			else if (nextln.equals("2")){
				option = 2;
				Server server = new Server();
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
