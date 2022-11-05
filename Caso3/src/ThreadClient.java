import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ThreadClient extends Thread{

	private static SecurityFunctions f;
	private Socket sc;
	private int id;
	public static PublicKey publicaServidor;
	
	public ThreadClient(Socket sc, int id) {
		this.sc = sc;
		this.id = id;
	}
	
	public void run() {
		try {
			f = new SecurityFunctions();
			//Create scanner to read from console

			//Create reader and writer
			//ac sends data to server
			PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
			//dc receives data from server
			BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));

			//Get public key (is supposed to be public so I think there is no trouble in just copying it)
			publicaServidor = f.read_kplus("datos_asim_srv.pub","Server public key: ");

			//1.
			//Send request to server
			ac.println("SECURE INIT");

			//3.
			//Get diffie-Hellman data
			BigInteger g = new BigInteger(dc.readLine());
			BigInteger p = new BigInteger(dc.readLine());
			BigInteger commonVal = new BigInteger(dc.readLine());



			//Create our diffie-helman Y value 
			SecureRandom r = new SecureRandom();
			int x = Math.abs(r.nextInt());
			Long longx = Long.valueOf(x);
			BigInteger bix = BigInteger.valueOf(longx);
			//6a.
			long startG2X = System.nanoTime();
			BigInteger myVal = G2X(g, bix, p);
			long endG2X = System.nanoTime();      
		    System.out.println("Cliente "+id+" --- Elapsed Time for G2X computation in nano seconds: "+ (endG2X-startG2X));
			//4.
			//get F(K+,m) 
			String gPGxMsgSigned = dc.readLine();
			try {
				long startSig = System.nanoTime();
				boolean check = f.checkSignature(
						publicaServidor,
						str2byte(gPGxMsgSigned),
						// expected message
						g + "," + p + "," + commonVal
						);
				long endSig = System.nanoTime();      
			    System.out.println("Cliente "+id+" --- Elapsed Time for Signature verification in nano seconds: "+ (endSig-startSig));
				//5.
				ac.println(check ? "OK" : "ERROR");
			} catch (Exception e) {
				// TODO should we be sending this when the signature check throws an exception?
				//      or should we only do it when the signature check actually returns false?

				// JC:I think this is fine as if it throws an exception it means the signature is invalid and it should not continue
				ac.println("ERROR");
			}

			//6b.
			//Send value
			ac.println(myVal.toString());

			//7a.
			//Get master key
			BigInteger masterKey = G2X(commonVal, bix, p);
			String strMasterKey = masterKey.toString();

			try {
				//Get symetric keys
				SecretKey sk_clt = f.csk1(strMasterKey);
				SecretKey sk_mac = f.csk2(strMasterKey);
				//Get vector
				byte[] iv1 = generateIvBytes();
				IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
				//Aks for consultation
				Random rdm = new Random();
				int intCons = rdm.nextInt(100);
				String consulta = Integer.toString(intCons);
				//Encrypt
				byte[] encMsg = f.senc(consulta.getBytes("UTF-8"), sk_clt, ivSpec1, "Cliente "+ this.id);
				//hmac
				long startHMAC = System.nanoTime();
				byte[] macMsg = f.hmac(consulta.getBytes("UTF-8"), sk_mac);
				long endHMAC = System.nanoTime();      
			    System.out.println("Cliente "+id+" --- Elapsed Time for HMAC generation in nano seconds: "+ (endHMAC-startHMAC)); 

				//8.
				//Send
				ac.println(byte2str(encMsg));
				ac.println(byte2str(macMsg));
				ac.println(byte2str(iv1));

				//10.
				String confirmation = dc.readLine();
				//It never generates the error so this is never used but I did it bc why not
				if(confirmation.equals("ERROR")) System.exit(1);
				//11.
				//Get data from server
				String encMsg2 = dc.readLine();
				String macMsg2 = dc.readLine();
				String iv2 = dc.readLine();
				byte[] encMsgBytes = str2byte(encMsg2);
				byte[] macMsgBytes = str2byte(macMsg2);

				byte[] ivBytes = str2byte(iv2);
				IvParameterSpec ivSpec2 = new IvParameterSpec(ivBytes);    
				//Decrypt
				byte[] decMsg = f.sdec(encMsgBytes, sk_clt, ivSpec2);
				//12.
				//Check hmac
				boolean verify  = f.checkInt(decMsg, sk_mac, macMsgBytes);
				//13.
				ac.println((verify)?"OK":"ERROR");
			} catch (Exception e) {
				e.printStackTrace();
			}
			ac.close();
			dc.close();
			sc.close();
		} catch (IOException e) {
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

	private byte[] generateIvBytes() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return iv;
	}
}
