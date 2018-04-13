package stgc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyStore;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import stgc.exceptions.InvalidAddressException;
import utils.Utils;
import utils.XmlParser;

final class AuthenticationServer {

	private static final String KEYSTORE_FILE = "res/keystore.jceks";
	private static final String KEYSTORE_PASSWORD = "password";
	private static final String JCEKS_VALUE = "*";
	private static final int MAX_PACKET_SIZE = 65507;
	
	@SuppressWarnings("resource")
	public static void main(String[] args) throws IOException {
		if (args.length != 5 ) {
			System.err.println("usage: Java AuthenticationServer multicastgroup port password salt iterations");
			System.exit(0);
		}
		InetAddress group = InetAddress.getByName(args[0]);
		if (!group.isMulticastAddress() ) {
			System.err.println("Multicast address required...");
			System.exit(0);
		}
		int port = 0;
		try {
			port = Integer.parseInt(args[1]);
		} catch (NumberFormatException e) { 
			System.out.println("Port is not a number"); 
			System.exit(0);
		}
		String password = args[2];
		String salt = args[3];
		int iterations = 0;
		try {
			iterations = Integer.parseInt(args[4]);
		} catch (NumberFormatException e) { 
			System.out.println("Iterations is not a number"); 
			System.exit(0);
		}
		Map<String, List<String>> dacl = new HashMap<String, List<String>>(5);
		STGCMulticastSocket socket = new STGCMulticastSocket(port, new PBEKeySpec(password.toCharArray(), Utils.toBytes(salt), iterations));
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
				String ciphersuite = getCiphersuite(ip);
				Key sessionKey = getSessionKey(ip);
				String macAlgorithm = getMacAlgorithm(ip);
				Key macKey = getMacKey(ip);
				TicketAS ticket = new TicketAS(user, ip, ciphersuite, sessionKey, macAlgorithm, macKey);
				AuthorizationReply authReply = new AuthorizationReply(digestedPassword, nouncePlusOne, nounceS, ticket);
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ObjectOutput o = new ObjectOutputStream(bos);   
				o.writeObject(authReply);
				o.flush();
				byte[] reply = bos.toByteArray();		
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
	
//	private static boolean isAuthorized(Map<String, List<String>> auths, String multicastIP, String user) {
//		List<String> users = auths.get(multicastIP);
//		return users != null && users.contains(user);
//	}

	private static Key getKeyFromKeystore(String key, String password) throws Exception {
		final KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(new File(KEYSTORE_FILE)), KEYSTORE_PASSWORD.toCharArray());
		return keyStore.getKey(key, password.toCharArray());
	}

	private static String getCiphersuite(String ip) throws Exception {
		return XmlParser.getRoomProperty(ip, "ciphersuite");
	}

	private static String getMacAlgorithm(String ip) throws Exception {
		return XmlParser.getRoomProperty(ip, "mac");
	}
	
	private static String getKeyValue(String ip) throws Exception {
		return XmlParser.getRoomProperty(ip, "keyvalue");
	}
	
	private static String getMacKeyValue(String ip) throws Exception {
		return XmlParser.getRoomProperty(ip, "mackeyvalue");
	}

	private static Key getSessionKey(String ip) throws Exception {
		Key sessionKey = null;
		String keyValue = getKeyValue(ip);
		if (!keyValue.equals(JCEKS_VALUE)) {
			String ciphersuite = getCiphersuite(ip);
			sessionKey = new SecretKeySpec(Utils.toBytes(keyValue), ciphersuite); 
		} else {
			sessionKey = getKeyFromKeystore("sessionkey", "password");
		}
		return sessionKey;
	}

	private static Key getMacKey(String ip) throws Exception {
		Key macKey = null;
		String macKeyValue = getMacKeyValue(ip);
		if (!macKeyValue.equals(JCEKS_VALUE)) {
			String macAlgorithm = getMacAlgorithm(ip);
			macKey = new SecretKeySpec(Utils.toBytes(macKeyValue), macAlgorithm);
		} else {
			macKey = getKeyFromKeystore("mackey", "password");
		}
		return macKey;
	}
	
}
