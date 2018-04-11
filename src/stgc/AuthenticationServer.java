package stgc;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import stgc.data_structures.LimitedSizeQueue;
import stgc.exceptions.DataIntegrityAuthenticityException;
import stgc.exceptions.DataReplyingException;
import stgc.exceptions.UserAuthenticationException;
import stgc.exceptions.UserUnregisteredException;
import utils.Utils;

public class AuthenticationServer {

	private static final String DACL_FILE = "res/dacl.conf";
	private static final String USERS_FILE = "res/users.conf";
	private static final String CIPHERSUITE_FILE = "res/ciphersuite.conf";
	private static final String KEYSTORE_FILE = "res/keystore.jceks";
	public static final int MAX_NOUNCES = 100;
	
	
	public static final int HEADER_SIZE = 6;
	// TODO
	public static final int VERSION = 1;
	public static final int RELEASE = 1;
	public static final byte SEPARATOR = 0x00;
	public static final String JCEKS_VALUE = "*";
	public static final int PACKET_HEADER_SIZE = 6;
	public static final String PROVIDER = "BC";
	public static final int MAX_ID_BYTES = 256;
	private static final int MAX_IP_BYTES = 32;
	


	@SuppressWarnings("resource")
	public static void main(String[] args) throws IOException {
		if (args.length != 2 ) {
			System.err.println("usage: Java AuthenticationServer multicast_group port") ;
			System.exit(0);
		}
		List<Integer> nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);

		final InetAddress group = InetAddress.getByName(args[0]);
		if (!group.isMulticastAddress() ) {
			System.err.println("Multicast address required...");
			System.exit(0);
		}
		final int port = Integer.parseInt(args[1]);
		STGCMulticastSocket socket = new STGCMulticastSocket(port);
		socket.joinGroup(group);
		byte[] buffer = new byte[65536];
		DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
		System.out.println("Waiting for auth requests at " + group.getHostAddress() + ":" + port + "...");
		for (;;) {	
			try {
				inPacket.setLength(65536); // resize with max size
				socket.recieveAuthRequest(inPacket);
				System.out.println("> Recieved auth request at " + new Date());
				ByteBuffer data = ByteBuffer.wrap(inPacket.getData());
				int nounce = data.getInt();
				byte[] password = new byte[MessageDigest.getInstance("SHA-512").getDigestLength()];
				data.get(password);
				DatagramPacket replyPacket = new DatagramPacket(new byte[65536], 65536, inPacket.getAddress(), inPacket.getPort());
				socket.sendAuthReply(replyPacket, nounce, new String(password)); //TODO nounce e password no packet
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static boolean isRegistered(String multicastIP, String user) throws IOException {
		//users.conf
		//tabela de autenticação de utilizadores, que mapeia utilizadores registados
		//(sendo o registo prévio e manual). Só utilizadores registados podem autenticar-se
		//		maria/maria@hotmail.com: H(password-da-maria)
		//		jose/jose@gmai.com: H(password-do-jose)
		//		jfaustino:/j.faustino@campus.fct.unl.pt: H(password-do-jfaustino)
		//TODO dividir file por salas
		return getPropertyValue("users.conf", user) != null;
	}

	private static boolean isAuthorized(String multicastIP, String user) throws IOException {
		//O servidor AS tem uma tabela DAC – Descritionary Acccess Control que não é mais do que um ficheiro de
		//controlo de acessos dacl.conf que tem o registo de autorizações de acesso a grupos multicast seguros
		// dacl.conf
		String users = getPropertyValue(DACL_FILE, multicastIP);
		String[] usersList = users.split(",");
		return Arrays.asList(usersList).contains(user);
	}

	private static String getPropertyValue(String file, String key) throws IOException {
		Properties properties = new Properties();
		properties.load(new FileInputStream(file));
		return properties.getProperty(key);
	}

	//	stgcsap.auth
	//	PBE: algoritmo PBE Encryptiom em causa, podendo ser usadas por exemplo:
	//	PBE=PBEWithSHAAnd3KeyTripleDES:HMacSHA1

	private static String getPBEAlgorithm() throws IOException {
		String cipherAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return cipherAndMac.split(":")[0];
	}

	private static String getMacAlgorithm() throws IOException {
		String cipherAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return Utils.subStringBetween(cipherAndMac, ':', ':');
	}


}
