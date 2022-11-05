import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Client {

	private static final String host = "localhost";
	private static final int port = 4030;
	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter the number of client delegates: ");
		int numDelegados = sc.nextInt();
		
		
		
		for (int i = 0; i < numDelegados; i++) {
			Socket socket = new Socket(host, port);
			ThreadClient delegado = new ThreadClient(socket, i);
			delegado.start();
		}
		
	}

}

