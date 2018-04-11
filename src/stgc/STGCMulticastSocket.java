package stgc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
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
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import stgc.data_structures.LimitedSizeQueue;
import stgc.exceptions.DataIntegrityAuthenticityException;
import stgc.exceptions.DataReplyingException;
import stgc.exceptions.DenialOfServiceException;
import stgc.exceptions.UnauthorizedException;
import stgc.exceptions.UserAuthenticationException;
import stgc.exceptions.UserUnregisteredException;
import utils.Utils;

public final class STGCMulticastSocket extends MulticastSocket {

	public static final int VERSION = 1;
	public static final int RELEASE = 1;
	public static final byte SEPARATOR = 0x00;
	public static final String JCEKS_VALUE = "*";
	public static final int HEADER_SIZE = 6;
	public static final int MAX_NOUNCES = 100;
	public static final String PROVIDER = "BC";
	public static final int MAX_ID_BYTES = 256;
	public static final int MAX_IP_BYTES = 32;
	public static final int MAX_TICKET_BYTES = 256;
	public static final int MAX_PACKET_SIZE = 65507;

	private static final String AUTH_SERVER_IP = "224.10.10.10";

	private List<Integer> nounces;
	private Map<String, TicketAS> tickets; // multicastIP -> ticket

	public STGCMulticastSocket(SocketAddress paramSocketAddress) throws IOException {
		super(paramSocketAddress);
		this.nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);
		this.tickets = new HashMap<String, TicketAS>();
	}

	public STGCMulticastSocket(int paramInt) throws IOException {
		super(paramInt);
		this.nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);
		this.tickets = new HashMap<String, TicketAS>();
	}

	public STGCMulticastSocket() throws IOException {
		super();
		this.nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);
		this.tickets = new HashMap<String, TicketAS>();
	}

	@Override
	public void send(DatagramPacket datagramPacket) throws IOException {
		try {
			sendMessage(datagramPacket);
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			throw new IOException("Unable to send packet: \n" + sw.toString());
		}
	}
	
	public void sendMessage(DatagramPacket packet) throws Exception {
		byte[] payload = encryptMessage(packet.getData());
		sendPayload(packet, payload, PayloadType.MESSAGE);
	}
	
	private byte[] encryptMessage(byte[] data) throws Exception {
		String cipherAlgorithm = getPropertyValue("src/ciphersuite.conf", "ciphersuite");
		Cipher cipher = Cipher.getInstance(cipherAlgorithm, PROVIDER);
		String macAlgorithm = getPropertyValue("src/ciphersuite.conf", "mac");
		// Cifrar Mp e MacKm (Mp) com a chave Ks
		SecretKey sessionKey = getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv(16)); //TODO iv
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		byte[] macKeys = buildMacKeys();
		SecretKey personalMessageMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, 0, macKeys.length/2), macAlgorithm);
		SecretKey contentMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, macKeys.length/2, macKeys.length), macAlgorithm);
		byte[] personalMessage = getPersonalMessage(data);
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
		byte[] content = new byte[cipher.getOutputSize(personalMessage.length + mac.getMacLength())];
		int contentLength = cipher.update(personalMessage, 0, personalMessage.length, content, 0);
		mac.init(personalMessageMacKey);
		mac.update(personalMessage);
		cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), content, contentLength);
		// Colocar um MacKa(C) no final do payload
		mac.init(contentMacKey);
		mac.update(content);
		byte[] payload = ByteBuffer.allocate(content.length + mac.getMacLength()).put(content).array();
		mac.doFinal(payload, content.length);
		return payload;
	}

	public AuthorizationRequest sendAuthRequest(DatagramPacket packet, String id, String sha512Password, String ip) throws Exception {
		AuthorizationRequest request = encryptAuthRequest(id, sha512Password, ip);
		sendPayload(packet, request.getPayload(), PayloadType.SAP_AUTH_REQUEST);
		return request;
	}
	
	private AuthorizationRequest encryptAuthRequest(String id, String sha512Password, String ip) throws Exception {
		byte[] idBytes = ByteBuffer.allocate(MAX_ID_BYTES).put(id.getBytes(StandardCharsets.UTF_8)).array();
		byte[] passwordBytes = sha512Password.getBytes(StandardCharsets.UTF_8);
		byte[] ipBytes = ByteBuffer.allocate(MAX_IP_BYTES).put(ip.getBytes(StandardCharsets.UTF_8)).array();
		int nounce = generateNounce();
		byte[] macContent = ByteBuffer
				.allocate(Integer.BYTES + ipBytes.length + passwordBytes.length)
				.putInt(nounce).put(ipBytes).put(passwordBytes)
				.array();
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		MessageDigest md5 = MessageDigest.getInstance("MD5", PROVIDER);
		byte[] md5Content = ByteBuffer
				.allocate(Integer.BYTES + passwordBytes.length)
				.putInt(nounce).put(passwordBytes)
				.array();
		SecretKey macKey = new SecretKeySpec(md5.digest(md5Content), macAlgorithm);
		mac.init(macKey);
		byte[] authenticatorContent = ByteBuffer
				.allocate(Integer.BYTES + ipBytes.length + passwordBytes.length + mac.getMacLength())
				.putInt(nounce).put(ipBytes).put(passwordBytes).put(mac.doFinal(macContent))
				.array();
		char[] passwordSeed = sha512Password.toCharArray();
		String pbeAlgorithm = getPBEAlgorithm();
		System.out.println("PBE Algorithm: " + pbeAlgorithm);
		System.out.println("Password (Hex): " + sha512Password);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
		int iterationCount = 2048;
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		cipher.init(Cipher.ENCRYPT_MODE, key); 
		byte[] authenticator = cipher.doFinal(authenticatorContent);		
		System.out.println("Authenticator (Hex): " + Utils.toHex(authenticator));
		byte[] payload = ByteBuffer
				.allocate(MAX_ID_BYTES + Integer.BYTES + MAX_IP_BYTES + authenticator.length)
				.put(idBytes).putInt(nounce).put(ipBytes).put(authenticator)
				.array();
		return new AuthorizationRequest(payload, nounce);
	}
	
	protected void sendAuthReply(DatagramPacket packet, int nounce, String sha512Password) throws Exception {
		byte[] payload = encryptAuthReply(nounce, sha512Password);
		sendPayload(packet, payload, PayloadType.SAP_AUTH_REPLY);
	}
	
	private byte[] encryptAuthReply(int nounce, String sha512Password) throws Exception {
		byte[] password = sha512Password.getBytes(StandardCharsets.UTF_8);
		int nouncePlus1 = nounce + 1;
		int nounceS = generateNounce();
		System.out.println("Server nounce: " + nounceS);
		TicketAS ticket = new TicketAS(); // TODO
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput o = new ObjectOutputStream(bos);   
		o.writeObject(ticket);
		o.flush();
		byte[] ticketBytes = ByteBuffer.allocate(MAX_TICKET_BYTES).put(bos.toByteArray()).array();
		// TODO definir max ticket size


		// Colocar um MacK(X) no final da mensagem
		// K = MD5(NonceC+1 || SHA-512(pwd))
		// X =  ( NonceC+1 || NonceS || TicketAS )
		byte[] md5Bytes = ByteBuffer
				.allocate(Integer.BYTES + password.length)
				.putInt(nouncePlus1).put(password)
				.array();
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		byte[] macKeySeed = md5.digest(md5Bytes);
		Key macKey = new SecretKeySpec(macKeySeed, macAlgorithm);
		mac.init(macKey);
		byte[] macBytes = ByteBuffer
				.allocate(Integer.BYTES + Integer.BYTES + MAX_TICKET_BYTES)
				.putInt(nouncePlus1)
				.putInt(nounceS)
				.put(ticketBytes)
				.array();
		mac.update(macBytes);
		byte[] bytesToCipher = ByteBuffer
				.allocate(Integer.BYTES + Integer.BYTES + ticketBytes.length + mac.getMacLength())
				.putInt(nouncePlus1)
				.putInt(nounceS)
				.put(ticketBytes)
				.array();
		mac.doFinal(bytesToCipher, Integer.BYTES + Integer.BYTES + ticketBytes.length);

		//TODO adicionar nounce aos nounces

		// passwordSeed = SHA-512(pwd) || NonceC+1
		String replyPassword = Utils.toHex(
				ByteBuffer
				.allocate(password.length + Integer.BYTES)
				.put(password).putInt(nouncePlus1)
				.array());
		System.out.println("Reply password: " + replyPassword);
		char[] passwordSeed = replyPassword.toCharArray();
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
		int iterationCount = 2048; // TODO
		String pbeAlgorithm = getPBEAlgorithm();
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] replyMessage = cipher.doFinal(bytesToCipher);
		return replyMessage;
	}
	
	private void sendPayload(DatagramPacket packet, byte[] payload, PayloadType payloadType) throws Exception {
		byte[] data = appendHeader(payload, payloadType);
		packet.setData(data);
		super.send(packet);
	}

	@Override
	public synchronized void receive(DatagramPacket datagramPacket) throws IOException {
		try {
			recieveMessage(datagramPacket);
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			throw new IOException("Unable to recieve packet: \n" + sw.toString());
		}
	}
	
	public void recieveMessage(DatagramPacket datagramPacket) throws Exception {
		super.receive(datagramPacket);
		ByteBuffer data = ByteBuffer.wrap(datagramPacket.getData()).asReadOnlyBuffer();
		Header header = getPacketHeader(data);
		byte[] message = decryptMessage(header, data);
		datagramPacket.setData(message);
	}

	private byte[] decryptMessage(Header header, ByteBuffer data) throws Exception {
		SecretKey sessionKey = getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv(16)); //TODO
		String macAlgorithm = getPropertyValue("src/ciphersuite.conf", "mac");
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		byte[] macKeys = buildMacKeys();
		SecretKey personalMessageMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, 0, macKeys.length/2), macAlgorithm);
		SecretKey contentMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, macKeys.length/2, macKeys.length), macAlgorithm);

		// Verificação Mac do conteudo cifrado da mensagem
		byte[] ciphered = new byte[header.getPayloadSize() - mac.getMacLength()];
		data.get(ciphered);
		byte[] cipheredHash = new byte[mac.getMacLength()];
		data.get(cipheredHash);
		mac.init(contentMacKey);
		if (!MessageDigest.isEqual(mac.doFinal(ciphered), cipheredHash)) {
			throw new DenialOfServiceException("Content MAC does not match.");
		}
		// Decifrar o conteúdo
		String cipherAlgorithm = getPropertyValue("src/ciphersuite.conf", "ciphersuite");
		System.out.println(cipherAlgorithm);
		Cipher cipher = Cipher.getInstance(cipherAlgorithm, PROVIDER);
		cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
		byte[] content = cipher.doFinal(ciphered);
		ByteBuffer personalMessage = ByteBuffer.wrap(Arrays.copyOfRange(content, 0, content.length - mac.getMacLength()));
		byte[] personalMessageHash = Arrays.copyOfRange(content, content.length - mac.getMacLength(), content.length);
		//		byte[] clientId = new byte[MAX_ID_BYTES];
		//		personalMessage.get(clientId);
		//		System.out.println(new String(clientId).trim());
		// Verificar o nounce para evitar a repetição de mensagens
		int nounce = personalMessage.getInt();
		if (nounces.contains(nounce)) {
			throw new DataReplyingException();
		}
		nounces.add(nounce);
		byte[] message = new byte[data.capacity()];
		personalMessage.get(message);
		// Verificação Mac da mensagem pessoal para mitigar ataques de integridade e autenticidade
		mac.init(personalMessageMacKey);
		if (!MessageDigest.isEqual(personalMessageHash, mac.doFinal(personalMessage.array()))) {
			throw new DataIntegrityAuthenticityException("Message Mac does not match.");
		}

		return message;
	}
	
	
	protected void recieveAuthRequest(DatagramPacket datagramPacket) throws Exception {
		super.receive(datagramPacket);
		ByteBuffer data = ByteBuffer.wrap(datagramPacket.getData()).asReadOnlyBuffer();
		Header header = getPacketHeader(data);
		byte[] authRequest = decryptAuthRequest(header, data);
		datagramPacket.setData(authRequest);
	}

	private byte[] decryptAuthRequest(Header header, ByteBuffer data) throws Exception {
		int messageHeaderSize = MAX_ID_BYTES + Integer.BYTES + MAX_IP_BYTES;
		int authSize = header.getPayloadSize() - messageHeaderSize;

		byte[] clientId = new byte[MAX_ID_BYTES];
		data.get(clientId);
		String client = new String(clientId).trim();
		System.out.println("Client: " + client);

		int nounceC = data.getInt(); // nounce
		System.out.println("Nounce: " + nounceC);

		if (nounces.contains(nounceC)) {
			throw new DataReplyingException();
		}
		nounces.add(nounceC);
		byte[] multicastIp = new byte[MAX_IP_BYTES];
		data.get(multicastIp);
		String ip = new String(multicastIp).trim();
		System.out.println("Multicast ip: " + ip);

		if (!isRegistered(ip, client)) {
			throw new UserUnregisteredException("User \"" + client + "\" is not registered at ip: " + ip);
		}
		byte[] cipherAuthenticator = new byte[authSize];
		data.get(cipherAuthenticator);
		System.out.println("Authenticator (Hex): " + Utils.toHex(cipherAuthenticator));

		String pbeAlgorithm = getPBEAlgorithm();
		System.out.println("PBE algorithm: " + pbeAlgorithm);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
		String password = Utils.subStringBetween(getPropertyValue("users.conf", client), '(', ')');
		System.out.println("Password (Hex): " + password);
		char[] passwordSeed = password.toCharArray(); // k1
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
		int iterationCount = 2048; // TODO
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		cipher.init(Cipher.DECRYPT_MODE, key);
		ByteBuffer auth = ByteBuffer.wrap(cipher.doFinal(cipherAuthenticator));
		int nounceAuth = auth.getInt();
		System.out.println("Nounce auth: " + nounceAuth);
		byte[] multicastIpAuth = new byte[MAX_IP_BYTES];
		auth.get(multicastIpAuth);
		System.out.println("Multicast ip auth: " + new String(multicastIpAuth).trim());
		byte[] passwordAuth = new byte[password.length()];
		auth.get(passwordAuth);
		System.out.println("Password auth (Hex): " + new String(passwordAuth).trim());
		String macAlgorithm = getMacAlgorithm();
		System.out.println("Mac algorithm: " + macAlgorithm);
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		byte[] macValue = new byte[mac.getMacLength()];
		auth.get(macValue);

		MessageDigest md5 = MessageDigest.getInstance("MD5", PROVIDER);
		byte[] message = ByteBuffer
				.allocate(Integer.BYTES + passwordAuth.length)
				.putInt(nounceAuth)
				.put(passwordAuth)
				.array();
		byte[] macKeySeed = md5.digest(message);
		SecretKey macKey = new SecretKeySpec(macKeySeed, macAlgorithm);
		mac.init(macKey);
		byte[] macBytes = ByteBuffer
				.allocate(Integer.BYTES + multicastIpAuth.length + passwordAuth.length)
				.putInt(nounceAuth)
				.put(multicastIpAuth)
				.put(passwordAuth)
				.array();
		if (!MessageDigest.isEqual(macValue, mac.doFinal(macBytes))) {
			throw new DataIntegrityAuthenticityException("Macs do not match.");
		}

		return ByteBuffer.allocate(data.capacity()).put(message).array();
	}
	
	private TicketAS recieveAuthReply(DatagramPacket datagramPacket, String sha512Password, int nounce) throws Exception {
		super.receive(datagramPacket);
		ByteBuffer data = ByteBuffer.wrap(datagramPacket.getData()).asReadOnlyBuffer();
		Header header = getPacketHeader(data);
		TicketAS ticket = decryptAuthReply(header, data, sha512Password, nounce);
		return ticket;
	}

	private TicketAS decryptAuthReply(Header header, ByteBuffer data, String sha512Password, int nounce) throws Exception {
		byte[] passwordBytes = sha512Password.getBytes(StandardCharsets.UTF_8);
		String decryptPassword = Utils.toHex(
				ByteBuffer.allocate(passwordBytes.length + Integer.BYTES)
				.put(passwordBytes).putInt(nounce + 1)
				.array());
		char[] passwordSeed = decryptPassword.toCharArray();
		System.out.println("Decrypt password: " + decryptPassword);
		String pbeAlgorithm = getPBEAlgorithm();
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
		int iterationCount = 2048; // TODO
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] replyCipher = new byte[header.getPayloadSize()];
		data.get(replyCipher);
		ByteBuffer reply = ByteBuffer.wrap(cipher.doFinal(replyCipher));
		int nounceCPlus1 = reply.getInt();
		int nounceS = reply.getInt();
		if (nounces.contains(nounceS)) {
			throw new DataReplyingException();
		}
		byte[] ticketBytes = new byte[MAX_TICKET_BYTES];
		reply.get(ticketBytes);
		ByteArrayInputStream bis = new ByteArrayInputStream(ticketBytes);
		ObjectInput in = new ObjectInputStream(bis);
		TicketAS ticket = (TicketAS)in.readObject(); 
		System.out.println(ticket.toString());
		byte[] macContent = ByteBuffer
				.allocate(Integer.BYTES + Integer.BYTES + MAX_TICKET_BYTES)
				.putInt(nounceCPlus1).putInt(nounceS).put(ticketBytes)
				.array();
		byte[] md5Content = ByteBuffer
				.allocate(Integer.BYTES + passwordBytes.length)
				.putInt(nounce+1).put(passwordBytes)
				.array();
		MessageDigest md5 = MessageDigest.getInstance("MD5", PROVIDER);
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		Key macKey = new SecretKeySpec(md5.digest(md5Content), macAlgorithm);
		mac.init(macKey);
		byte[] macValue = new byte[mac.getMacLength()];
		reply.get(macValue);
		if (MessageDigest.isEqual(macValue, mac.doFinal(macContent))) {
			throw new DataIntegrityAuthenticityException("Macs do not match");
		}
		return ticket;
	}

	private byte[] buildHeader(PayloadType payloadType, short payloadSize) {
		return ByteBuffer
				.allocate(HEADER_SIZE)
				.put(buildVersionRelease())
				.put(SEPARATOR)
				.put((byte)payloadType.code)
				.put(SEPARATOR)
				.putShort(payloadSize)
				.array();
	}

	private byte buildVersionRelease() {
		String versionBinary = Utils.intTo4Bits(VERSION);
		String releaseBinary = Utils.intTo4Bits(RELEASE);
		String versionReleaseBinary = versionBinary + releaseBinary;
		int versionReleaseDecimal = Integer.parseInt(versionReleaseBinary, 2);
		String versionReleaseHex = String.format("%02X", versionReleaseDecimal);
		byte versionReleaseByte = (byte) ((Character.digit(versionReleaseHex.charAt(0), 16) << 4) + Character.digit(versionReleaseHex.charAt(1), 16));
		return versionReleaseByte;
	}

	private byte[] appendHeader(byte[] payload, PayloadType payloadType) {
		byte[] header = buildHeader(payloadType, (short)payload.length);
		return ByteBuffer
				.allocate(header.length + payload.length)
				.put(header)
				.put(payload)
				.array();
	}

	private Header getPacketHeader(ByteBuffer data) {
		byte versionRelease = data.get();
		data.position(data.position()+1);
		char payloadType = (char)data.get(); // TODO data.getChar();
		data.position(data.position()+1);
		short payloadSize = data.getShort();
		Header header = new Header(versionRelease, payloadType, payloadSize);
		System.out.println("--- Packet header ---");
		System.out.println ("Version: " + header.getVersion());
		System.out.println("Release: " + header.getRelease());
		System.out.println("Payload type: " + header.getPayloadType());
		System.out.println("Payload size: " + header.getPayloadSize());
		System.out.println("---------------------");
		return header;
	}

	private byte[] buildMacKeys() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableEntryException, IOException, NoSuchProviderException {
		byte[] macKey = null;
		String macKeyValue = getPropertyValue("src/ciphersuite.conf", "mackeyvalue");
		if (!macKeyValue.equals(JCEKS_VALUE)) {
			macKey = macKeyValue.getBytes(StandardCharsets.UTF_8);
		} 
		else {
			macKey = getKeyStore("src/mykeystore.jceks", "password").getKey("mackey", "password".toCharArray()).getEncoded();
		}
		return MessageDigest.getInstance("SHA-256", PROVIDER).digest(macKey);
	}

	private String getPropertyValue(String file, String key) throws IOException {
		Properties properties = new Properties();
		properties.load(new FileInputStream(file));
		return properties.getProperty(key);
	}


	private SecretKey getSessionKey() 
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
		SecretKey sessionKey = null;
		String keyValue = getPropertyValue("src/ciphersuite.conf", "keyvalue");
		if (!keyValue.equals(JCEKS_VALUE)) {
			sessionKey = new SecretKeySpec(keyValue.getBytes(StandardCharsets.UTF_8), getPropertyValue("src/ciphersuite.conf", "ciphersuite")); 
		} else {
			final String keyStoreFile = "src/mykeystore.jceks";
			KeyStore keyStore = getKeyStore(keyStoreFile, "password");
			PasswordProtection keyPassword = new PasswordProtection("password".toCharArray());
			KeyStore.Entry entry = keyStore.getEntry("sessionkey", keyPassword);
			sessionKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
		}
		return sessionKey;
	}

	private byte[] createIv(int size) {
		/*byte[] ivBytes = new byte[size];
		SecureRandom random = new SecureRandom();
		random.nextBytes(ivBytes);
		return ivBytes;*/
		return new byte[] {
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
		};
	}

	private int generateNounce() {
		SecureRandom random = new SecureRandom();
		int nounce = random.nextInt();
		return nounce;
	}

	private byte[] getPersonalMessage(byte[] message) {
		String id = ""; // TODO
		int nounce = generateNounce();
		return ByteBuffer
				.allocate(Integer.BYTES + message.length)
				//.put(id.getBytes(StandardCharsets.UTF_8))
				.putInt(nounce)
				.put(message)
				.array();
	}

	private KeyStore getKeyStore(String fileName, String password) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		final KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(new File(fileName)), password.toCharArray());
		return keyStore;
	}

	@Override
	public void joinGroup(InetAddress multicastIp) throws IOException {
		//		String ip = multicastIp.getHostAddress();
		//		if (!hasAccess(ip)) {
		//			throw new UnauthorizedException("Unauthorized to join " + ip);
		//		}
		super.joinGroup(multicastIp);
	}

	@Override
	public void joinGroup(SocketAddress socketAddress, NetworkInterface networkInterface) throws IOException {
		throw new UnsupportedOperationException();
	}

	private boolean hasAccess(String multicastIp) {
		return multicastIp.equals(AUTH_SERVER_IP) || tickets.containsKey(multicastIp);
	}

	@Override
	public void leaveGroup(InetAddress multicastIp) throws IOException {
		super.leaveGroup(multicastIp);
		String ip = multicastIp.getHostAddress();
		tickets.remove(ip);
	}

	public void requestAuthorization(String id, String password, InetAddress group) throws Exception {
		// Send message to Authentication Server 
		String sha512Password = Utils.toHex(MessageDigest.getInstance("SHA-512", PROVIDER).digest(password.getBytes(StandardCharsets.UTF_8)));
		DatagramPacket requestPacket = new DatagramPacket(new byte[65536], 65536, InetAddress.getByName(AUTH_SERVER_IP), 3000);
		AuthorizationRequest request = sendAuthRequest(requestPacket, id, sha512Password, group.getHostAddress());
		// and recieve reply message
		DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
		TicketAS ticket = recieveAuthReply(p, sha512Password, request.getNounce());
		System.out.println("Recieved reply packet at " + new Date());
		tickets.put(group.getHostAddress(), ticket);
	}

	private String getPBEAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[0];
	}

	private String getMacAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[1];
	}

	private boolean isRegistered(String multicastIP, String user) throws IOException {
		//users.conf
		//tabela de autenticação de utilizadores, que mapeia utilizadores registados
		//(sendo o registo prévio e manual). Só utilizadores registados podem autenticar-se
		//		maria/maria@hotmail.com: H(password-da-maria)
		//		jose/jose@gmai.com: H(password-do-jose)
		//		jfaustino:/j.faustino@campus.fct.unl.pt: H(password-do-jfaustino)
		//TODO dividir file por salas
		return getPropertyValue("users.conf", user) != null;
	}

}
