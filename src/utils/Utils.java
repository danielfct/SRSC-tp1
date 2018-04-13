package utils;

import java.io.FileInputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Utils {

	private final static char[] hexArray = "0123456789abcdef".toCharArray();
	
	public static String toHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public static String toHex(int ch) {
		return String.format("%04x", (int) ch);
	}
	
	public static byte[] toBytes(String hex) {
	    int len = hex.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
	                             + Character.digit(hex.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static String intTo4Bits(int n) {
		if (n < 0) {
			throw new IllegalArgumentException("Argument is negative");
		}
		if (n > 15) {
			throw new IllegalArgumentException("Only integers lower than 16 can be stored in 4 bits");
		}
		String binary = "";
		for	(int i = 0; i < 4; ++i, n/=2) {
			binary = n % 2 + binary;
		}
		return binary;
	}
	
	public static int generateNounce() {
		SecureRandom random = new SecureRandom();
		int nounce = random.nextInt();
		return nounce;
	}
	
	public static String decryptFile(PBEKeySpec pbeKeySpec, String file) throws Exception {
		// Read ciphered text
		FileInputStream fis = new FileInputStream(file);
	    byte[] cipherText = new byte[fis.available()];
	    fis.read(cipherText);
	    fis.close();
	    // Decipher text
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
		Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
	    byte[] plainText = cipher.doFinal(cipherText);
		return new String(plainText);
	}

	public static String substringBetween(String exp, char first, char second) {
		String expression = exp.substring(exp.indexOf(first) + 1);
		return expression.substring(0, expression.indexOf(second));
	}

	
}
