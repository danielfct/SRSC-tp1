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
		mac.init(contentMacKey);
		mac.update(content);
		byte[] payload = ByteBuffer.allocate(content.length + mac.getMacLength()).put(content).array();
		mac.doFinal(payload, content.length);
		return payload;
	}

	private void sendAuthRequest(DatagramPacket packet) throws Exception {
		ByteBuffer data = ByteBuffer.wrap(packet.getData());
		byte[] id = new byte[data.getInt()];
		data.get(id);
		byte[] digestPassword = new byte[data.getInt()];
		data.get(digestPassword); //TODo objecto?
		byte[] ip = new byte[data.getInt()];
		data.get(ip);
		int nounce = data.getInt();
		byte[] payload = encryptAuthRequest(new String(id), new String(digestPassword), new String(ip), nounce);
		sendPayload(packet, payload, PayloadType.SAP_AUTH_REQUEST);
	}

	private byte[] encryptAuthRequest(String id, String digestedPassword, String ip, int nounce) throws Exception {
		byte[] idBytes = ByteBuffer.allocate(MAX_ID_BYTES).put(id.getBytes(StandardCharsets.UTF_8)).array();
		byte[] passwordBytes = digestedPassword.getBytes(StandardCharsets.UTF_8);
		byte[] ipBytes = ByteBuffer.allocate(MAX_IP_BYTES).put(ip.getBytes(StandardCharsets.UTF_8)).array();
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm, PROVIDER);
		byte[] macKeyContent = ByteBuffer
				.allocate(Integer.BYTES + passwordBytes.length)
				.putInt(nounce).put(passwordBytes)
				.array();
		SecretKey macKey = new SecretKeySpec(msgDigest.digest(macKeyContent), macAlgorithm);
		mac.init(macKey);
		byte[] macContent = ByteBuffer
				.allocate(Integer.BYTES + ipBytes.length + passwordBytes.length)
				.putInt(nounce).put(ipBytes).put(passwordBytes)
				.array();
		byte[] authenticatorContent = ByteBuffer
				.allocate(Integer.BYTES + ipBytes.length + passwordBytes.length + mac.getMacLength())
				.putInt(nounce).put(ipBytes).put(passwordBytes).put(mac.doFinal(macContent))
				.array();
		char[] passwordSeed = digestedPassword.toCharArray();
		String pbeAlgorithm = getPBEAlgorithm();
		System.out.println("PBE Algorithm: " + pbeAlgorithm);
		System.out.println("Password (Hex): " + digestedPassword);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
		int iterationCount = 2048;
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		cipher.init(Cipher.ENCRYPT_MODE, key); 
		byte[] authenticator = cipher.doFinal(authenticatorContent);
		System.out.println(authenticator.length);
		System.out.println("Authenticator (Hex): " + Utils.toHex(authenticator));
		byte[] payload = ByteBuffer
				.allocate(MAX_ID_BYTES + Integer.BYTES + MAX_IP_BYTES + authenticator.length)
				.put(idBytes).putInt(nounce).put(ipBytes).put(authenticator)
				.array();
		return payload;
	}

	protected void sendAuthReply(DatagramPacket packet) throws Exception {
		ByteBuffer data = ByteBuffer.wrap(packet.getData());
		int nounce = data.getInt();
		int passwordSize = data.getInt();
		byte[] digestedPassword = new byte[passwordSize];
		data.get(digestedPassword);
		byte[] payload = encryptAuthReply(nounce, new String(digestedPassword));
		sendPayload(packet, payload, PayloadType.SAP_AUTH_REPLY);
	}

	private byte[] encryptAuthReply(int nounce, String digestedPassword) throws Exception {
		int nouncePlus1 = nounce + 1;
		int nounceS = generateNounce();
		TicketAS ticket = new TicketAS(); //TODO
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput o = new ObjectOutputStream(bos);   
		o.writeObject(ticket);
		o.flush();
		byte[] ticketBytes = ByteBuffer.allocate(MAX_TICKET_BYTES).put(bos.toByteArray()).array();
		byte[] digestContent = (Integer.toHexString(nouncePlus1) + digestedPassword).getBytes(StandardCharsets.UTF_8);
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm);
		byte[] macKeySeed = msgDigest.digest(digestContent);
		Key macKey = new SecretKeySpec(macKeySeed, macAlgorithm);
		mac.init(macKey);
		byte[] bytesToCipher = ByteBuffer
				.allocate(Integer.BYTES + Integer.BYTES + ticketBytes.length + mac.getMacLength())
				.putInt(nouncePlus1).putInt(nounceS).put(ticketBytes)
				.array();
		mac.update(bytesToCipher, 0, Integer.BYTES + Integer.BYTES + ticketBytes.length);
		mac.doFinal(bytesToCipher, Integer.BYTES + Integer.BYTES + ticketBytes.length);

		//TODO adicionar nounce aos nounces

		String replyPassword = digestedPassword + Integer.toHexString(nouncePlus1);
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
		ByteBuffer dataWriter = (ByteBuffer)ByteBuffer.wrap(datagramPacket.getData()).position(datagramPacket.getOffset());
		ByteBuffer dataReader = dataWriter.duplicate().asReadOnlyBuffer();
		Header header = getPacketHeader(dataReader);
		if (header.getPayloadType() == PayloadType.MESSAGE.code) {
			byte[] message = decryptMessage(header, dataReader);
			dataWriter.put(message);
			datagramPacket.setData(dataWriter.array());
		}
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
		ByteBuffer dataWriter = (ByteBuffer)ByteBuffer.wrap(datagramPacket.getData()).position(datagramPacket.getOffset());
		ByteBuffer dataReader = dataWriter.duplicate().asReadOnlyBuffer();
		Header header = getPacketHeader(dataReader);
		if (header.getPayloadType() == PayloadType.SAP_AUTH_REQUEST.code) {
			AuthorizationRequest auth = decryptAuthRequest(header, dataReader);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutput o = new ObjectOutputStream(bos);   
			o.writeObject(auth);
			o.flush();
			dataWriter.put(bos.toByteArray());
			datagramPacket.setData(dataWriter.array());
		}
	}

	private AuthorizationRequest decryptAuthRequest(Header header, ByteBuffer data) throws Exception {
		// Obter informação não cifrada
		byte[] clientId = new byte[MAX_ID_BYTES];
		data.get(clientId);
		String client = new String(clientId).trim();
		int nounce = data.getInt();
		if (nounces.contains(nounce)) {
			throw new DataReplyingException();
		}
		nounces.add(nounce);
		byte[] multicastIp = new byte[MAX_IP_BYTES];
		data.get(multicastIp);
		String ip = new String(multicastIp).trim();
		byte[] cipheredAuth = new byte[header.getPayloadSize() - (data.position() - HEADER_SIZE)];
		data.get(cipheredAuth);
		System.out.println("Auth (hex): " + Utils.toHex(cipheredAuth));

		// Decifrar o autenticador
		String pbeAlgorithm = getPBEAlgorithm();
		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
		String password = Utils.subStringBetween(getPropertyValue("users.conf", client), '(', ')');
		System.out.println("Client password (hex): " + password);
		char[] passwordSeed = password.toCharArray();
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
		int iterationCount = 2048; // TODO
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		cipher.init(Cipher.DECRYPT_MODE, key);

		// Obter informação cifrada
		ByteBuffer decipheredAuth = ByteBuffer.wrap(cipher.doFinal(cipheredAuth));
		int nounceAuth = decipheredAuth.getInt();
		byte[] multicastIpAuth = new byte[MAX_IP_BYTES];
		decipheredAuth.get(multicastIpAuth);
		String ipAuth = new String(multicastIpAuth).trim();
		byte[] passwordAuth = new byte[password.length()];
		decipheredAuth.get(passwordAuth);
		String passAuth = new String(passwordAuth);
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		byte[] macValue = new byte[mac.getMacLength()];
		decipheredAuth.get(macValue);
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm, PROVIDER);
		byte[] macKeyContent = ByteBuffer
				.allocate(Integer.BYTES + passwordAuth.length)
				.putInt(nounceAuth).put(passwordAuth)
				.array();
		byte[] macKeySeed = msgDigest.digest(macKeyContent);
		SecretKey macKey = new SecretKeySpec(macKeySeed, macAlgorithm);
		mac.init(macKey);
		byte[] macBytes = ByteBuffer
				.allocate(Integer.BYTES + multicastIpAuth.length + passwordAuth.length)
				.putInt(nounceAuth).put(multicastIpAuth).put(passwordAuth)
				.array();
		if (!MessageDigest.isEqual(macValue, mac.doFinal(macBytes))) {
			throw new DataIntegrityAuthenticityException("Macs do not match.");
		}	

		// Devolver o pedido para ser processado pelo servidor de autenticação
		Authenticator auth = new Authenticator(nounceAuth, ipAuth, passAuth);
		AuthorizationRequest request = new AuthorizationRequest(client, nounce, ip, auth);
		return request;
	}

	private void recieveAuthReply(DatagramPacket datagramPacket, String password, int nounce) throws Exception {
		super.receive(datagramPacket);
		ByteBuffer dataWriter = (ByteBuffer)ByteBuffer.wrap(datagramPacket.getData()).position(datagramPacket.getOffset());
		ByteBuffer dataReader = dataWriter.duplicate().asReadOnlyBuffer();
		Header header = getPacketHeader(dataReader);
		if (header.getPayloadType() == PayloadType.SAP_AUTH_REPLY.code) {
			TicketAS ticket = decryptAuthReply(header, dataReader, password, nounce);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutput o = new ObjectOutputStream(bos);   
			o.writeObject(ticket);
			o.flush();
			dataWriter.put(bos.toByteArray());
			datagramPacket.setData(dataWriter.array());
			//TODO juntar recieves todos
		}
	}

	private TicketAS decryptAuthReply(Header header, ByteBuffer payload, String digestedPassword, int nounce) throws Exception {
		String decryptPassword = digestedPassword + Integer.toHexString(nounce + 1);
		System.out.println(decryptPassword);
		byte[] passwordBytes = decryptPassword.getBytes(StandardCharsets.UTF_8);
		char[] passwordSeed = decryptPassword.toCharArray();
		String pbeAlgorithm = getPBEAlgorithm();
		System.out.println("Pbe algorithm: " + pbeAlgorithm);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm, PROVIDER);
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; 	// TODO salt e count
		int iterationCount = 2048; // TODO
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm, PROVIDER);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] replyMessage = new byte[header.getPayloadSize()];
		payload.get(replyMessage);
		ByteBuffer reply = ByteBuffer.wrap(cipher.doFinal(replyMessage));
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
		byte[] digestContent = ByteBuffer
				.allocate(Integer.BYTES + passwordBytes.length)
				.putInt(nounce+1).put(passwordBytes)
				.array();
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm, PROVIDER);
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm, PROVIDER);
		Key macKey = new SecretKeySpec(msgDigest.digest(digestContent), macAlgorithm);
		mac.init(macKey);
		byte[] macValue = new byte[mac.getMacLength()];
		reply.get(macValue);
		if (MessageDigest.isEqual(macValue, mac.doFinal(macContent))) {
			throw new DataIntegrityAuthenticityException("Macs do not match");
		}
		return ticket; //TODO authreply
	}

	private byte[] appendHeader(byte[] payload, PayloadType payloadType) {
		return ByteBuffer
				.allocate(HEADER_SIZE + payload.length)
				.put(buildVersionRelease()).put(SEPARATOR).put((byte)payloadType.code).put(SEPARATOR).putShort((short)payload.length)
				.put(payload)
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

	private Header getPacketHeader(ByteBuffer data) {
		byte versionRelease = data.get();
		data.position(data.position()+1);
		char payloadType = (char)data.get();
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
		// Send Request
		byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
		String passwordDigestAlgorithm = getPasswordDigestAlgorithm();
		MessageDigest passwordDigest = MessageDigest.getInstance(passwordDigestAlgorithm, PROVIDER);
		String digestedPassword = Utils.toHex(passwordDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		byte[] passwordBytes = digestedPassword.getBytes(StandardCharsets.UTF_8);
		byte[] ipBytes = group.getHostAddress().getBytes(StandardCharsets.UTF_8);
		int nounce = generateNounce();
		byte[] request = ByteBuffer
				.allocate(Integer.BYTES + idBytes.length + Integer.BYTES + passwordBytes.length + Integer.BYTES + ipBytes.length + Integer.BYTES)
				.putInt(idBytes.length)
				.put(idBytes)
				.putInt(passwordBytes.length)
				.put(passwordBytes)
				.putInt(ipBytes.length)
				.put(ipBytes)
				.putInt(nounce)
				.array();
		DatagramPacket requestPacket = new DatagramPacket(request, request.length, InetAddress.getByName(AUTH_SERVER_IP), 3000);
		sendAuthRequest(requestPacket);
		// And recieve reply
		DatagramPacket reply = new DatagramPacket(new byte[MAX_PACKET_SIZE], MAX_PACKET_SIZE);
		recieveAuthReply(reply, digestedPassword, nounce);
		ByteArrayInputStream bis = new ByteArrayInputStream(reply.getData());
		ObjectInput in = new ObjectInputStream(bis);
		TicketAS ticket = (TicketAS)in.readObject(); //TODO mudar para authreply

		System.out.println("Recieved reply packet at " + new Date());
		tickets.put(group.getHostAddress(), ticket);
	}

	private String getPBEAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[0];
	}

	private String getPasswordDigestAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[1];
	}

	public String getMacKeyDigestAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[2];
	}

	private String getMacAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[3];
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
