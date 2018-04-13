package utils;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class FileEncryption {

	public static void main(String[] args) throws Exception {
		if (args.length != 3) {
			System.err.println("usage: Java FileEncryption inputfile outputfile password") ;
			System.exit(0);
		}
		String inputfile = args[0];
		String outputfile = args[1];
		String password = args[2];
		FileInputStream inFile = new FileInputStream(inputfile);
		FileOutputStream outFile = new FileOutputStream(outputfile);
		String passwordHash = Utils.toHex(MessageDigest.getInstance("SHA-512").digest(password.getBytes(StandardCharsets.UTF_8)));
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[8];
		random.nextBytes(salt);
		int iterations = random.nextInt(2048);
		PBEKeySpec pbeKeySpec = new PBEKeySpec(passwordHash.toCharArray(), salt, iterations);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
		Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] input = new byte[64];
		int bytesRead;
		while ((bytesRead = inFile.read(input)) != -1) {
			byte[] output = cipher.update(input, 0, bytesRead);
			if (output != null)
				outFile.write(output);
		}
		byte[] output = cipher.doFinal();
		if (output != null)
			outFile.write(output);
		inFile.close();
		outFile.flush();
		outFile.close();
		System.out.println("Input file: " + inputfile);
		System.out.println("Password: " + passwordHash);
		System.out.println("Salt: " + Utils.toHex(salt));
		System.out.println("Iterations: " + iterations);
		System.out.println("Output file: " + outputfile);
	}

}
