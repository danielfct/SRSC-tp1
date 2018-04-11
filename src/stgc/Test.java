package stgc;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;

import utils.Utils;

import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

public class Test {


	public static void main(String args[]) throws NoSuchAlgorithmException {
//		byte v = buildVersionRelease();
//		String versionReleaseBinary = String.format("%8s", Integer.toBinaryString((int)v)).replace(' ', '0'); 
//		String version = versionReleaseBinary.substring(0, 4);
//		System.out.println(Integer.parseInt(version, 2));
		
		
		System.out.println(ByteBuffer.wrap(new byte[5]).capacity());
	}
	
	public static byte buildVersionRelease() {
		String versionBinary = Utils.intTo4Bits(2);
		String releaseBinary = Utils.intTo4Bits(1);
		String versionReleaseBinary = versionBinary + releaseBinary;
		int versionReleaseDecimal = Integer.parseInt(versionReleaseBinary, 2);
		String versionReleaseHex = String.format("%02X", versionReleaseDecimal);
		byte versionReleaseByte = (byte) ((Character.digit(versionReleaseHex.charAt(0), 16) << 4) + Character.digit(versionReleaseHex.charAt(1), 16));
		return versionReleaseByte;
	}

	public static String get_SHA_512_SecurePassword(String passwordToHash){
		String generatedPassword = null;
		    try {
		         MessageDigest md = MessageDigest.getInstance("SHA-512");
		         byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
		         StringBuilder sb = new StringBuilder();
		         for(int i=0; i< bytes.length ;i++){
		            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
		         }
		         generatedPassword = sb.toString();
		        } 
		       catch (NoSuchAlgorithmException e){
		        e.printStackTrace();
		       }
		    return generatedPassword;
		}
	

	public static String sha512() throws NoSuchAlgorithmException {
		byte[] passwordBytes = "password".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
		byte[] saltedHash = messageDigest.digest(passwordBytes);
		return Base64.getEncoder().encodeToString(saltedHash);
	}

}
