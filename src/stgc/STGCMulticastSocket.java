package stgc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import stgc.data_structures.LimitedSizeQueue;
import stgc.exceptions.DataIntegrityAuthenticityException;
import stgc.exceptions.DataReplyingException;
import stgc.exceptions.DenialOfServiceException;
import stgc.exceptions.UnauthorizedException;
import stgc.exceptions.UserUnregisteredException;
import utils.Utils;
import utils.XmlParser;

public final class STGCMulticastSocket extends MulticastSocket {

	private static final int VERSION = 1;
	private static final int RELEASE = 1;
	private static final byte SEPARATOR = 0x00;
	private static final int HEADER_SIZE = 6;
	private static final int MAX_NOUNCES = 100;
	private static final int MAX_ID_BYTES = 256;
	private static final int MAX_IP_BYTES = 32;
	private static final int MAX_TICKET_BYTES = 1024;
	private static final int MAX_PACKET_SIZE = 65507;

	private static final String AUTH_SERVER_IP = "224.224.224.224";
	private static final int AUTH_SERVER_PORT = 3001;

	private List<Integer> nounces;
	private Map<String, TicketAS> tickets; // multicastIP -> ticket
	private PBEKeySpec pbeKeySpec;

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

	STGCMulticastSocket(int paramInt, PBEKeySpec pbeKeySpec) throws IOException {
		super(paramInt);
		this.pbeKeySpec = pbeKeySpec;
		this.nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);
		this.tickets = new HashMap<String, TicketAS>();
	}

	@Override
	public void send(DatagramPacket packet) throws IOException {
		try {
			String user = Utils.substringBetween(new String(packet.getData()), '<', '>');
			byte[] msg = Arrays.copyOfRange(packet.getData(), user.length()+2, packet.getData().length);
			sendMessage(packet, msg, user);
		} catch (Exception e) {
			e.printStackTrace();
			throw new IOException(e.getMessage());
		}
	}

	public void sendMessage(DatagramPacket packet, byte[] msg, String user) throws Exception {
		byte[] payload = encryptMessage(msg, user, packet.getAddress().getHostAddress());
		byte[] ip = ByteBuffer.allocate(MAX_IP_BYTES).put(packet.getAddress().getHostAddress().getBytes(StandardCharsets.UTF_8)).array();
		byte[] data = ByteBuffer.allocate(ip.length + payload.length).put(ip).put(payload).array();
		sendPayload(packet, data, PayloadType.MESSAGE);
	}

	private byte[] encryptMessage(byte[] msg, String user, String ip) throws Exception {
		TicketAS ticket = tickets.get(ip);
		if (ticket == null) {
			throw new UnauthorizedException("Não tem autorização para enviar pacotes para o endereço " + ip);
		}
		if (ticket.isExpired()) {
			tickets.remove(ip);
			throw new UnauthorizedException("A autorização ao endereço " + ip + " expirou");
		}
		String cipherAlgorithm = ticket.getCiphersuite();
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);
		String macAlgorithm = ticket.getMac();
		Key sessionKey = ticket.getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv());
		Mac mac = Mac.getInstance(macAlgorithm);
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] macKeys = sha256.digest(Utils.toHex(ticket.getMacKey().getEncoded()).getBytes(StandardCharsets.UTF_8));
		SecretKey personalMessageMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, 0, macKeys.length/2), macAlgorithm);
		SecretKey contentMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, macKeys.length/2, macKeys.length), macAlgorithm);
		int nounce = Utils.generateNounce();
		byte[] username = ByteBuffer.allocate(MAX_ID_BYTES).put(user.getBytes(StandardCharsets.UTF_8)).array();
		byte[] personalMessage = ByteBuffer
				.allocate(MAX_ID_BYTES + Integer.BYTES + msg.length)
				.put(username)
				.putInt(nounce)
				.put(msg)
				.array();
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
		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));
		String username = istream.readUTF();
		String digestedPassword = istream.readUTF();
		String multicastIp = istream.readUTF();
		int nounce = istream.readInt();
		byte[] payload = encryptAuthRequest(username, digestedPassword, multicastIp, nounce);
		sendPayload(packet, payload, PayloadType.SAP_AUTH_REQUEST);
	}

	private byte[] encryptAuthRequest(String id, String digestedPassword, String ip, int nounce) throws Exception {
		byte[] idBytes = ByteBuffer.allocate(MAX_ID_BYTES).put(id.getBytes(StandardCharsets.UTF_8)).array();
		byte[] passwordBytes = digestedPassword.getBytes(StandardCharsets.UTF_8);
		byte[] ipBytes = ByteBuffer.allocate(MAX_IP_BYTES).put(ip.getBytes(StandardCharsets.UTF_8)).array();
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm);
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm);
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
		Cipher cipher = Cipher.getInstance(pbeAlgorithm);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm);
		byte[] salt = Utils.toBytes(getSalt());
		int iterationCount = getIterations();
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		cipher.init(Cipher.ENCRYPT_MODE, key); 
		byte[] authenticator = cipher.doFinal(authenticatorContent);
		byte[] payload = ByteBuffer
				.allocate(MAX_ID_BYTES + Integer.BYTES + MAX_IP_BYTES + authenticator.length)
				.put(idBytes).putInt(nounce).put(ipBytes).put(authenticator)
				.array();
		return payload;
	}

	protected void sendAuthReply(DatagramPacket packet) throws Exception {
		ByteArrayInputStream bis = new ByteArrayInputStream(packet.getData());
		ObjectInput in = new ObjectInputStream(bis);
		AuthorizationReply authReply = (AuthorizationReply)in.readObject();
		byte[] payload = encryptAuthReply(authReply);
		sendPayload(packet, payload, PayloadType.SAP_AUTH_REPLY);
	}

	private byte[] encryptAuthReply(AuthorizationReply authReply) throws Exception {
		String digestedPassword = authReply.getDigestedPassword();
		int nouncePlusOne = authReply.getNouncePlusOne();
		int nounceS = authReply.getNounceS();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput o = new ObjectOutputStream(bos);   
		o.writeObject(authReply.getTicket());
		o.flush();
		byte[] ticketBytes = ByteBuffer.allocate(MAX_TICKET_BYTES).put(bos.toByteArray()).array();
		String encryptPassword = Integer.toHexString(nouncePlusOne) + digestedPassword;
		byte[] digestContent = encryptPassword.getBytes(StandardCharsets.UTF_8);
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm);
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm);
		byte[] macKeySeed = msgDigest.digest(digestContent);
		Key macKey = new SecretKeySpec(macKeySeed, macAlgorithm);
		mac.init(macKey);
		byte[] bytesToCipher = ByteBuffer
				.allocate(Integer.BYTES + Integer.BYTES + ticketBytes.length + mac.getMacLength())
				.putInt(nouncePlusOne).putInt(nounceS).put(ticketBytes)
				.array();
		mac.update(bytesToCipher, 0, Integer.BYTES + Integer.BYTES + ticketBytes.length);
		mac.doFinal(bytesToCipher, Integer.BYTES + Integer.BYTES + ticketBytes.length);
		String replyPassword = digestedPassword + Integer.toHexString(nouncePlusOne);
		char[] passwordSeed = replyPassword.toCharArray();
		String ip = authReply.getTicket().getIp();
		String user = authReply.getTicket().getClient();
		byte[] salt = Utils.toBytes(XmlParser.getUserProperty(pbeKeySpec, ip, user, "salt"));
		int iterationCount = Integer.valueOf(XmlParser.getUserProperty(pbeKeySpec, ip, user, "iterations"));
		String pbeAlgorithm = getPBEAlgorithm();
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm);
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm);
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
			e.printStackTrace();
			throw new IOException(e.getLocalizedMessage());
		}
	}

	public void recieveMessage(DatagramPacket packet) throws Exception {
		super.receive(packet);
		//System.out.println("> Recieved message at " + new Date());
		ByteBuffer dataWriter = (ByteBuffer)ByteBuffer.wrap(packet.getData()).position(packet.getOffset());
		ByteBuffer dataReader = dataWriter.duplicate().asReadOnlyBuffer();
		Header header = getPacketHeader(dataReader);
		byte[] message = decryptMessage(header, dataReader);
		dataWriter.put(message);
		packet.setData(dataWriter.array(), packet.getOffset(), message.length);
	}

	private byte[] decryptMessage(Header header, ByteBuffer data) throws Exception {
		byte[] ipBytes = new byte[MAX_IP_BYTES];
		data.get(ipBytes);
		String ip = new String(ipBytes).trim();
		TicketAS ticket = tickets.get(ip);
		if (ticket == null) {
			throw new UnauthorizedException("O utilizador não está autorizado a receber mensagens de " + ip);
		}
		if (ticket.isExpired()) {
			tickets.remove(ip);
			throw new UnauthorizedException("A autorização ao endereço " + ip + " expirou");
		}
		Key sessionKey = ticket.getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv());
		String macAlgorithm = ticket.getMac();
		Mac mac = Mac.getInstance(macAlgorithm);
		byte[] macKeys = MessageDigest.getInstance("SHA-256").digest(Utils.toHex(ticket.getMacKey().getEncoded()).getBytes(StandardCharsets.UTF_8));
		SecretKey personalMessageMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, 0, macKeys.length/2), macAlgorithm);
		SecretKey contentMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, macKeys.length/2, macKeys.length), macAlgorithm);
		byte[] ciphered = new byte[header.getPayloadSize() - MAX_IP_BYTES - mac.getMacLength()];
		data.get(ciphered);
		byte[] cipheredHash = new byte[mac.getMacLength()];
		data.get(cipheredHash);
		mac.init(contentMacKey);
		if (!MessageDigest.isEqual(mac.doFinal(ciphered), cipheredHash)) {
			throw new DenialOfServiceException("Content MAC does not match.");
		}
		String cipherAlgorithm = ticket.getCiphersuite();
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
		ByteBuffer content = ByteBuffer.wrap(cipher.doFinal(ciphered));
		mac.init(personalMessageMacKey);
		byte[] mp = new byte[content.capacity() - mac.getMacLength()];
		content.get(mp);
		byte[] mpHash = new byte[mac.getMacLength()];
		content.get(mpHash);
		ByteBuffer personalMessage = ByteBuffer.wrap(mp);
		byte[] clientId = new byte[MAX_ID_BYTES];
		personalMessage.get(clientId);
		int nounce = personalMessage.getInt();
		if (nounces.contains(nounce)) {
			throw new DataReplyingException();
		}
		nounces.add(nounce);
		byte[] message = new byte[personalMessage.capacity() - personalMessage.position()];
		personalMessage.get(message);
		if (!MessageDigest.isEqual(mpHash, mac.doFinal(personalMessage.array()))) {
			throw new DataIntegrityAuthenticityException("Message Mac does not match.");
		}
		return message;
	}

	protected void recieveAuthRequest(DatagramPacket packet) throws Exception {
		super.receive(packet);
		ByteBuffer dataWriter = (ByteBuffer)ByteBuffer.wrap(packet.getData()).position(packet.getOffset());
		ByteBuffer dataReader = dataWriter.duplicate().asReadOnlyBuffer();
		Header header = getPacketHeader(dataReader);
		AuthorizationRequest auth = decryptAuthRequest(header, dataReader);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput o = new ObjectOutputStream(bos);   
		o.writeObject(auth);
		o.flush();
		byte[] data = bos.toByteArray();
		dataWriter.put(data);
		packet.setData(dataWriter.array(), packet.getOffset(), data.length);
	}

	private AuthorizationRequest decryptAuthRequest(Header header, ByteBuffer data) throws Exception {
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
		// Decifrar o autenticador
		String pbeAlgorithm = getPBEAlgorithm();
		Cipher cipher = Cipher.getInstance(pbeAlgorithm);
		if (!isRegistered(ip, client)) {
			throw new UserUnregisteredException("User \"" + client + "\" is not registered at ip " + ip);
		}
		String password = XmlParser.getUserProperty(pbeKeySpec, ip, client, "passwordhash");
		char[] passwordSeed = password.toCharArray();
		byte[] salt = Utils.toBytes(XmlParser.getUserProperty(pbeKeySpec, ip, client, "salt"));
		int iterationCount = Integer.valueOf(XmlParser.getUserProperty(pbeKeySpec, ip, client, "iterations"));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm);
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
		Mac mac = Mac.getInstance(macAlgorithm);
		byte[] macValue = new byte[mac.getMacLength()];
		decipheredAuth.get(macValue);
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm);
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
		Authenticator auth = new Authenticator(nounceAuth, ipAuth, passAuth);
		AuthorizationRequest request = new AuthorizationRequest(client, nounce, ip, auth);
		return request;
	}

	private void recieveAuthReply(DatagramPacket packet, String password, int nounce) throws Exception {
		super.receive(packet);
		ByteBuffer dataWriter = (ByteBuffer)ByteBuffer.wrap(packet.getData()).position(packet.getOffset());
		ByteBuffer dataReader = dataWriter.duplicate().asReadOnlyBuffer();
		Header header = getPacketHeader(dataReader);
		TicketAS ticket = decryptAuthReply(header, dataReader, password, nounce);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput o = new ObjectOutputStream(bos);   
		o.writeObject(ticket);
		o.flush();
		byte[] data = bos.toByteArray();
		dataWriter.put(data);
		packet.setData(dataWriter.array(), packet.getOffset(), data.length);
	}

	private TicketAS decryptAuthReply(Header header, ByteBuffer payload, String digestedPassword, int nounce) throws Exception {
		String decryptPassword = digestedPassword + Integer.toHexString(nounce + 1);
		byte[] passwordBytes = decryptPassword.getBytes(StandardCharsets.UTF_8);
		char[] passwordSeed = decryptPassword.toCharArray();
		String pbeAlgorithm = getPBEAlgorithm();
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm);
		byte[] salt = Utils.toBytes(getSalt());
		int iterationCount = getIterations();
		PBEKeySpec keySpec = new PBEKeySpec(passwordSeed, salt, iterationCount);
		Key key = keyFactory.generateSecret(keySpec);
		Cipher cipher = Cipher.getInstance(pbeAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] replyMessage = new byte[header.getPayloadSize()];
		payload.get(replyMessage);
		ByteBuffer reply = ByteBuffer.wrap(cipher.doFinal(replyMessage));
		int nounceCPlus1 = reply.getInt();
		int nounceS = reply.getInt();
		if (nounces.contains(nounceS)) {
			throw new DataReplyingException();
		}
		nounces.add(nounceS);
		byte[] ticketBytes = new byte[MAX_TICKET_BYTES];
		reply.get(ticketBytes);
		ByteArrayInputStream bis = new ByteArrayInputStream(ticketBytes);
		ObjectInput in = new ObjectInputStream(bis);
		TicketAS ticket = (TicketAS)in.readObject();
		byte[] macContent = ByteBuffer
				.allocate(Integer.BYTES + Integer.BYTES + MAX_TICKET_BYTES)
				.putInt(nounceCPlus1).putInt(nounceS).put(ticketBytes)
				.array();
		byte[] digestContent = ByteBuffer
				.allocate(Integer.BYTES + passwordBytes.length)
				.putInt(nounce+1).put(passwordBytes)
				.array();
		String macKeyDigestAlgorithm = getMacKeyDigestAlgorithm();
		MessageDigest msgDigest = MessageDigest.getInstance(macKeyDigestAlgorithm);
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm);
		Key macKey = new SecretKeySpec(msgDigest.digest(digestContent), macAlgorithm);
		mac.init(macKey);
		byte[] macValue = new byte[mac.getMacLength()];
		reply.get(macValue);
		if (MessageDigest.isEqual(macValue, mac.doFinal(macContent))) {
			throw new DataIntegrityAuthenticityException("Macs do not match");
		}
		return ticket;
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
//		System.out.println("--- Packet header ---");
//		System.out.println ("Version: " + header.getVersion());
//		System.out.println("Release: " + header.getRelease());
//		System.out.println("Payload type: " + header.getPayloadType());
//		System.out.println("Payload size: " + header.getPayloadSize());
//		System.out.println("---------------------");
		return header;
	}

	private byte[] createIv() {
		return new byte[] {
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
		};
	}

	@Override
	public void joinGroup(InetAddress multicastIp) throws IOException {
		String ip = multicastIp.getHostAddress();
		if (!hasAccess(ip)) {
			throw new UnauthorizedException("Unauthorized to join " + ip);
		}
		super.joinGroup(multicastIp);
	}

	@Override
	public void joinGroup(SocketAddress socketAddress, NetworkInterface networkInterface) throws IOException {
		InetSocketAddress addr = (InetSocketAddress)socketAddress;
		String ip = addr.getAddress().getHostAddress();
		if (!hasAccess(ip)) {
			throw new UnauthorizedException("Unauthorized to join " + ip);
		}
		super.joinGroup(socketAddress, networkInterface);
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

	public void requestAuthorization(String username, String password, InetAddress group) throws Exception {
		// Send Request
		String passwordDigestAlgorithm = getPasswordDigestAlgorithm();
		MessageDigest passwordDigest = MessageDigest.getInstance(passwordDigestAlgorithm);
		String digestedPassword = Utils.toHex(passwordDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		int nounce = Utils.generateNounce();
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);
		dataStream.writeUTF(username);
		dataStream.writeUTF(digestedPassword);
		dataStream.writeUTF(group.getHostAddress());
		dataStream.writeInt(nounce);
		dataStream.close();
		byte[] data = byteStream.toByteArray();
		DatagramPacket requestPacket = new DatagramPacket(data, data.length, InetAddress.getByName(AUTH_SERVER_IP), AUTH_SERVER_PORT);
		//System.out.println("> Sending authorization request at " + new Date());
		sendAuthRequest(requestPacket);
		// And recieve reply
		DatagramPacket replyPacket = new DatagramPacket(new byte[MAX_PACKET_SIZE], MAX_PACKET_SIZE);
		recieveAuthReply(replyPacket, digestedPassword, nounce);
		ByteArrayInputStream bis = new ByteArrayInputStream(replyPacket.getData());
		ObjectInput in = new ObjectInputStream(bis);
		TicketAS ticket = (TicketAS)in.readObject();
		//System.out.println("> Recieved authorization reply at " + new Date());
		//System.out.println(ticket);
		tickets.put(group.getHostAddress(), ticket);
	}

	// Properties

	private boolean isRegistered(String multicastIp, String user) throws Exception {
		return XmlParser.getUserProperties(pbeKeySpec, multicastIp, user) != null;
	}

	private String getPropertyValue(String file, String key) throws IOException {
		Properties properties = new Properties();
		properties.load(new FileInputStream(file));
		return properties.getProperty(key);
	}

	private String getSalt() throws IOException {
		String pbe = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbe.split(":")[0];
	}

	private int getIterations() throws IOException {
		String pbe = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return Integer.valueOf(pbe.split(":")[1]);
	}

	private String getPBEAlgorithm() throws IOException {
		String pbe = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbe.split(":")[2];
	}

	private String getPasswordDigestAlgorithm() throws IOException {
		String pbe = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbe.split(":")[3];
	}

	public String getMacKeyDigestAlgorithm() throws IOException {
		String pbe = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbe.split(":")[4];
	}

	private String getMacAlgorithm() throws IOException {
		String pbe = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbe.split(":")[5];
	}

}
