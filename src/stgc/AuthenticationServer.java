package stgc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
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
	public static final int MAX_PACKET_SIZE = 65507;
	


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
				AuthorizationRequest req = (AuthorizationRequest)in.readObject();
				System.out.println(req);
				// TODO verificar autenticidade do utilizador
				
				if (!isRegistered(req.getIp(), req.getId())) {
					throw new UserUnregisteredException("User \"" + req.getId() + "\" is not registered at ip: " + req.getIp());
				}
				int nounce = req.getAuth().getNounce();
				byte[] digestedPassword = req.getAuth().getDigestedPassword().getBytes(StandardCharsets.UTF_8);
				byte[] reply = ByteBuffer
						.allocate(MAX_PACKET_SIZE)
						.putInt(nounce).putInt(digestedPassword.length).put(digestedPassword)
						.array();
				socket.sendAuthReply(new DatagramPacket(reply, reply.length, inPacket.getAddress(), inPacket.getPort()));
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

	private static String getPBEAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[0];
	}
	
	private static String getPasswordDigestAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[1];
	}
	
	public static String getMacKeyDigestAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[2];
	}

	private static String getMacAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[3];
	}


//	private AuthorizationRequest decryptAuthRequest(Header header, ByteBuffer data) throws Exception {
//		int messageHeaderSize = MAX_ID_BYTES + Integer.BYTES + MAX_IP_BYTES;
//		int authSize = header.getPayloadSize() - messageHeaderSize;
//
//		byte[] clientId = new byte[MAX_ID_BYTES];
//		data.get(clientId);
//		String client = new String(clientId).trim();
//		System.out.println("Client: " + client);
//		int nounceC = data.getInt(); // nounce
//		System.out.println("Nounce: " + nounceC);
//		if (nounces.contains(nounceC)) {
//			throw new DataReplyingException();
//		}
//		nounces.add(nounceC);
//		byte[] multicastIp = new byte[MAX_IP_BYTES];
//		data.get(multicastIp);
//		String ip = new String(multicastIp).trim();
//		System.out.println("Multicast ip: " + ip);
//
//		if (!isRegistered(ip, client)) {
//			throw new UserUnregisteredException("User \"" + client + "\" is not registered at ip: " + ip);
//		}
//		byte[] cipherAuthenticator = new byte[authSize];
//		data.get(cipherAuthenticator);
//		System.out.println("Authenticator (Hex): " + Utils.toHex(cipherAuthenticator));
//
//		String pbeAlgorithm = getPBEAlgorithm();
//		System.out.println("PBE algorithm: " + pbeAlgorithm);
//		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
//		String password = Utils.subStringBetween(getPropertyValue("users.conf", client), '(', ')');
//		System.out.println("Password (Hex): " + password);
//		char[] passwordSeed = password.toCharArray(); // k1
//		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
//		int iterationCount = 2048; // TODO
//		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
//		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
//		Key key = keyFactory.generateSecret(keySpec);
//		cipher.init(Cipher.DECRYPT_MODE, key);
//		ByteBuffer auth = ByteBuffer.wrap(cipher.doFinal(cipherAuthenticator));
//		int nounceAuth = auth.getInt();
//		System.out.println("Nounce auth: " + nounceAuth);
//		byte[] multicastIpAuth = new byte[MAX_IP_BYTES];
//		auth.get(multicastIpAuth);
//		System.out.println("Multicast ip auth: " + new String(multicastIpAuth).trim());
//		byte[] passwordAuth = new byte[password.length()];
//		auth.get(passwordAuth);
//		System.out.println("Password auth (Hex): " + new String(passwordAuth));
//		String macAlgorithm = getMacAlgorithm();
//		System.out.println("Mac algorithm: " + macAlgorithm);
//		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
//		byte[] macValue = new byte[mac.getMacLength()];
//		auth.get(macValue);
//
//		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
//		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm, PROVIDER);
//		byte[] message = ByteBuffer
//				.allocate(Integer.BYTES + passwordAuth.length)
//				.putInt(nounceAuth)
//				.put(passwordAuth)
//				.array();
//		byte[] macKeySeed = msgDigest.digest(message);
//		SecretKey macKey = new SecretKeySpec(macKeySeed, macAlgorithm);
//		mac.init(macKey);
//		byte[] macBytes = ByteBuffer
//				.allocate(Integer.BYTES + multicastIpAuth.length + passwordAuth.length)
//				.putInt(nounceAuth)
//				.put(multicastIpAuth)
//				.put(passwordAuth)
//				.array();
//		if (!MessageDigest.isEqual(macValue, mac.doFinal(macBytes))) {
//			throw new DataIntegrityAuthenticityException("Macs do not match.");
//		}
//
//		return ByteBuffer.allocate(data.capacity()).put(message).array();
//	}
	
	
	

}
