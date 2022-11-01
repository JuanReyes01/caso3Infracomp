import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;

public class Client {

    SecurityFunctions f;
    public Client(Socket sc) {
        try {
            f = new SecurityFunctions();
            //Create scanner to read from console
            Scanner scanner = new Scanner(System.in);
            
            //Create reader and writer
            //ac sends data to server
            PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
            //dc receives data from server
            BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));
            
            //Get public key (is supposed to be public so I think there is no trouble in just copying it)
            PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub","Server public key: ");

            //Reading request (we should make this automatic for the final tests)
            System.out.println("Reading request: ");
            String request = scanner.nextLine();
            //Send request to server
            ac.println(request);
            
            //Get diffie-Hellman data

            BigInteger g = new BigInteger(dc.readLine());
            BigInteger p = new BigInteger(dc.readLine());
            BigInteger commonVal = new BigInteger(dc.readLine());
            System.out.println("Received Diffie-Hellman data: ");
            System.out.println("g: " + g);
            System.out.println("p: " + p);
            System.out.println("commonVal: " + commonVal);
            
            //Create our diffie-helman Y value 
            SecureRandom r = new SecureRandom();
			int x = Math.abs(r.nextInt());
    		Long longx = Long.valueOf(x);
    		BigInteger bix = BigInteger.valueOf(longx);
            BigInteger myVal = G2X(g, bix, p);
            //Send value
            ac.println(myVal.toString());

            //Get key
            BigInteger key = G2X(commonVal, bix, p);
            


        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws Exception {
        //Server connection
        String ip = "127.0.0.1"; //Localhost
        Socket socket = null; 
        try {
            //Create socket
            socket = new Socket(ip, 4030);
            System.out.println("Conectado");
            Client c = new Client(socket);
            socket.close();
        } catch (Exception e) {
            System.out.println(e);
        }
    }
    private BigInteger G2X(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}

}

