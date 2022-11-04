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

            //1.
            //Send request to server
            ac.println("SECURE INIT");
            
            //3.
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
            
            //Get dh
            BigInteger dh = G2X(commonVal, bix, p);

            //4.
            //get F(K+,m) 
            //Esto me desencripta algo que no es (deberia funcionar(hay otro test en el que manda error a proposito))
            //Sospecho que es algo que tiene que ver con el byte[]
            String gPGxMsgSigned = dc.readLine();
            System.out.println("\nReceived signature: " + gPGxMsgSigned);
            try {
                boolean check = f.checkSignature(
                    publicaServidor,
                    str2byte(gPGxMsgSigned),
                    // expected message
                    g + "," + p + "," + commonVal
                );
                ac.println(check ? "OK" : "ERROR");
            } catch (Exception e) {
                // TODO should we be sending this when the signature check throws an exception?
                //      or should we only do it when the signature check actually returns false?
                ac.println("ERROR");
            }
            
            //Send value
            ac.println(myVal.toString());
            


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
            e.printStackTrace();
        }
    }

    private BigInteger G2X(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}

    public byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}

}

