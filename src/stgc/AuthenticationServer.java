package stgc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
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
import stgc.exceptions.InvalidAddressException;
import stgc.exceptions.UserAuthenticationException;
import stgc.exceptions.UserUnregisteredException;
import utils.Utils;

public class AuthenticationServer {

	private static final String DACL_FILE = "res/dacl.conf";
	private static final String USERS_FILE = "res/users.conf";
	private static final String CIPHERSUITE_FILE = "res/ciphersuite.conf";
	private static final String KEYSTORE_FILE = "res/keystore.jceks";
	private static final String KEYSTORE_PASSWORD = "password";
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
	public static final int MAX_PACKET_SIZE = 65507;

	@SuppressWarnings("resource")
	public static void main(String[] args) throws IOException {
		if (args.length != 2 ) {
			System.err.println("usage: Java AuthenticationServer multicast_group port") ;
			System.exit(0);
		}

		final InetAddress group = InetAddress.getByName(args[0]);
		if (!group.isMulticastAddress() ) {
			System.err.println("Multicast address required...");
			System.exit(0);
		}
		final int port = Integer.parseInt(args[1]);
		Map<String, List<String>> dacl = new HashMap<String, List<String>>(5);
		STGCMulticastSocket socket = new STGCMulticastSocket(port);
		socket.joinGroup(group);
		byte[] buffer = new byte[MAX_PACKET_SIZE];
		DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
		System.out.println("Waiting for auth requests at " + group.getHostAddress() + ":" + port + "...");
		for (;;) {	
			try {
				inPacket.setLength(MAX_PACKET_SIZE); // resize with max size
				socket.recieveAuthRequest(inPacket);
				System.out.println("> Recieved auth request at " + new Date());
				ByteArrayInputStream bis = new ByteArrayInputStream(inPacket.getData());
				ObjectInput in = new ObjectInputStream(bis);
				AuthorizationRequest authReq = (AuthorizationRequest)in.readObject();
				System.out.println(authReq);
				// TODO verificar autenticidade do utilizador
				String user = authReq.getId();
				String ip = authReq.getIp();
				int nounce = authReq.getNounce();
				Authenticator auth = authReq.getAuth();

				if (ip.equals(group.getHostAddress())) {
					throw new InvalidAddressException("Ip \"" + ip + "\" is reserved to Authentication Server.");
				}

				String digestedPassword = auth.getDigestedPassword();
				int nouncePlusOne = nounce + 1;
				int nounceS = Utils.generateNounce();
				String ciphersuite = getCiphersuite();
				Key sessionKey = getKeyFromKeystore("sessionkey", "password");
				String macAlgorithm = getMacAlgorithm();
				Key macKey = getKeyFromKeystore("mackey", "password");
				TicketAS ticket = new TicketAS(user, ip, ciphersuite, sessionKey, macAlgorithm, macKey);
				AuthorizationReply authReply = new AuthorizationReply(digestedPassword, nouncePlusOne, nounceS, ticket);
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ObjectOutput o = new ObjectOutputStream(bos);   
				o.writeObject(authReply);
				o.flush();
				byte[] reply = bos.toByteArray();
				System.out.println("port: " + inPacket.getPort());
				socket.sendAuthReply(new DatagramPacket(reply, reply.length, inPacket.getAddress(), inPacket.getPort()));
				
				List<String> users = dacl.get(ip);
				if (users == null) {
					users = new LinkedList<String>();
				}
				users.add(user);
				dacl.put(ip, users);
				
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static Key getKeyFromKeystore(String key, String password) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
			FileNotFoundException, IOException, UnrecoverableKeyException {
		final KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(new File(KEYSTORE_FILE)), KEYSTORE_PASSWORD.toCharArray());
		return keyStore.getKey(key, password.toCharArray());
	}

	private static boolean isAuthorized(Map<String, List<String>> auths, String multicastIP, String user) {
		List<String> users = auths.get(multicastIP);
		return users != null && users.contains(user);
	}

	private static String getPropertyValue(String file, String key) throws IOException {
		Properties properties = new Properties();
		properties.load(new FileInputStream(file));
		return properties.getProperty(key);
	}

	private static String getCiphersuite() throws IOException {
		return getPropertyValue(CIPHERSUITE_FILE, "ciphersuite");
	}

	private static String getMacAlgorithm() throws IOException {
		return getPropertyValue(CIPHERSUITE_FILE, "mac");
	}

}
