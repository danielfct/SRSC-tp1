package stgc_tlp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
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

import stgc_sap.TicketAS;
import stgc_tlp.data_structures.LimitedSizeQueue;
import stgc_tlp.exceptions.DenialOfServiceException;
import stgc_tlp.exceptions.UnauthorizedException;
import stgc_tlp.exceptions.UserAuthenticationException;
import utils.Utils;
import stgc_tlp.exceptions.DataIntegrityAuthenticityException;
import stgc_tlp.exceptions.DataReplyingException;

public final class STGCMulticastSocket extends MulticastSocket {

	public static final int VERSION = 1;
	public static final int RELEASE = 1;
	public static final byte SEPARATOR = 0x00;
	public static final String JCEKS_VALUE = "*";
	public static final int HEADER_SIZE = 6;
	public static final int MAX_NOUNCES = 100;
	public static final String PROVIDER = "BC";
	public static final int MAX_ID_BYTES = 10 + 256; // 10 chars (nickname) + 256 chars (email)

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
		this.sendMessage(datagramPacket);
	}

	private void sendMessage(DatagramPacket datagramPacket) throws IOException {
		byte[] data;
		try {
			data = encryptMessage(datagramPacket.getData());
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			throw new IOException("Unable to encrypt message: \n" + sw.toString());
		}
		datagramPacket.setData(data);
		super.send(datagramPacket);
	}

	//	private void sendAuthRequest(DatagramPacket datagramPacket) throws IOException {
	//		byte[] data = null;
	//		try {
	//			data = encryptAuthRequest(datagramPacket.getData());
	//		} catch (Exception e) {
	//			StringWriter sw = new StringWriter();
	//			e.printStackTrace(new PrintWriter(sw));
	//			throw new IOException("Unable to encrypt authorization request: \n" + sw.toString());
	//		}
	//		datagramPacket.setData(data);
	//		super.send(datagramPacket);
	//	}

	@Override
	public synchronized void receive(DatagramPacket datagramPacket) throws IOException {
		super.receive(datagramPacket);
		try {
			processMessage(datagramPacket);
		} catch (InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| UnrecoverableEntryException | NoSuchPaddingException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

	}

	private byte[] encryptMessage(byte[] data) 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, 
			NoSuchPaddingException, KeyStoreException, CertificateException, 
			UnrecoverableEntryException, ShortBufferException, IllegalBlockSizeException, 
			BadPaddingException, IllegalStateException, NoSuchProviderException, InvalidAlgorithmParameterException {
		byte[] payload = buildPayload(data);
		byte[] header = buildHeader(PayloadType.MESSAGE, (short)payload.length);
		return ByteBuffer
				.allocate(header.length + payload.length)
				.put(header)
				.put(payload)
				.array();
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
		String versionBinary = intTo4Bits(VERSION);
		String releaseBinary = intTo4Bits(RELEASE);
		String versionReleaseBinary = versionBinary + releaseBinary;
		int versionReleaseDecimal = Integer.parseInt(versionReleaseBinary, 2);
		String versionReleaseHex = String.format("%02X", versionReleaseDecimal);
		byte versionReleaseByte = (byte) ((Character.digit(versionReleaseHex.charAt(0), 16) << 4) + Character.digit(versionReleaseHex.charAt(1), 16));
		return versionReleaseByte;
	}

	private String intTo4Bits(int n) {
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

	private byte[] buildPayload(byte[] data) 
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
			KeyStoreException, CertificateException, UnrecoverableEntryException, 
			InvalidKeyException, ShortBufferException, IllegalBlockSizeException, 
			BadPaddingException, IllegalStateException, NoSuchProviderException, InvalidAlgorithmParameterException {

		Cipher cipher = Cipher.getInstance(getPropertyValue("src/ciphersuite.conf", "ciphersuite"), PROVIDER);
		String macAlgorithm = getPropertyValue("src/ciphersuite.conf", "mac");
		// Cifrar Mp e MacKm (Mp) com a chave Ks
		SecretKey sessionKey = getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv(16)); //TODO iv
		Mac mac = Mac.getInstance(macAlgorithm);
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

	private void processMessage(DatagramPacket datagramPacket) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
			UnrecoverableEntryException, IOException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException, 
			IllegalBlockSizeException, BadPaddingException {
		byte[] data = datagramPacket.getData();
		ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE).put(data, 0, HEADER_SIZE);
		byte versionRelease = header.get(0);
		char payloadType = (char)header.get(2);
		short payloadSize = header.getShort(4);
		if (payloadType == PayloadType.MESSAGE.code) {
			decryptPayload(datagramPacket, payloadSize);
		}	
		else if (payloadType == PayloadType.MESSAGE.code) {
			// decrypt auth
		}
	}

	private void decryptPayload(DatagramPacket datagramPacket, int payloadSize)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, IOException, InvalidKeyException, 
			InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		SecretKey sessionKey = getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv(16));
		String macAlgorithm = getPropertyValue("src/ciphersuite.conf", "mac");
		Mac mac = Mac.getInstance(macAlgorithm);
		byte[] macKeys = buildMacKeys();
		SecretKey personalMessageMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, 0, macKeys.length/2), macAlgorithm);
		SecretKey contentMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, macKeys.length/2, macKeys.length), macAlgorithm);

		byte[] payload = Arrays.copyOfRange(datagramPacket.getData(), HEADER_SIZE, HEADER_SIZE + payloadSize);
		// Verificação Mac do conteúdo para evitar ataques de disponibilidade
		mac.init(contentMacKey);
		int contentSize = payloadSize - mac.getMacLength();
		mac.update(payload, 0, contentSize);
		byte[] contentHash = Arrays.copyOfRange(payload, contentSize, payloadSize);
		if (!MessageDigest.isEqual(mac.doFinal(), contentHash)) {
			throw new DenialOfServiceException("Content MAC does not match.");
		}
		// Decifrar o conteúdo
		Cipher cipher = Cipher.getInstance(getPropertyValue("src/ciphersuite.conf", "ciphersuite"));
		cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
		byte[] content = cipher.doFinal(payload, 0, contentSize);
		int personalMessageSize = content.length - mac.getMacLength();
		int messageSize = personalMessageSize - Integer.BYTES; // - size of id
		ByteBuffer personalMessage = ByteBuffer.allocate(personalMessageSize).put(content, 0, personalMessageSize);
		// Verificar o nounce para evitar a repetição de mensagens
		int nounce = personalMessage.getInt(0);
		if (nounces.contains(nounce)) {
			throw new DataReplyingException();
		}
		nounces.add(nounce);
		// Verificação Mac da mensagem pessoal para mitigar ataques de integridade e autenticidade
		mac.init(personalMessageMacKey);
		mac.update(content, 0, personalMessageSize);
		byte[] messageHash = Arrays.copyOfRange(content, personalMessageSize, content.length);
		if (!MessageDigest.isEqual(mac.doFinal(), messageHash)) {
			throw new DataIntegrityAuthenticityException("Message Mac does not match.");
		}
		// Obter a mensagem inicial
		byte[] message = ByteBuffer.allocate(datagramPacket.getData().length).put(personalMessage.array(), Integer.BYTES, messageSize).array();
		datagramPacket.setData(message, 0, messageSize);
	}

	private byte[] buildMacKeys() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableEntryException, IOException {
		byte[] macKey = null;
		String macKeyValue = getPropertyValue("src/ciphersuite.conf", "mackeyvalue");
		if (!macKeyValue.equals(JCEKS_VALUE)) {
			macKey = macKeyValue.getBytes(StandardCharsets.UTF_8);
		} 
		else {
			macKey = getKeyStore("src/mykeystore.jceks", "password").getKey("mackey", "password".toCharArray()).getEncoded();
		}
		return MessageDigest.getInstance("SHA-256").digest(macKey);
	}

	private String getPropertyValue(String file, String key) throws IOException {
		Properties properties = new Properties();
		properties.load(new FileInputStream(file));
		return properties.getProperty(key);
	}
	//
	//	private int getKeySize(String key, String password) 
	//			throws KeyStoreException, NoSuchAlgorithmException, 
	//			CertificateException, IOException, 
	//			UnrecoverableEntryException {
	//		String keySize = getPropertyValue("keysize");
	//		if (keySize.equals(JCEKS_VALUE)) {
	//			final String keyStoreFile = "src/mykeystore.jceks"; 
	//			KeyStore keyStore = getKeyStore(keyStoreFile, "password");
	//			PasswordProtection keyPassword = new PasswordProtection(password.toCharArray());
	//			KeyStore.Entry entry = keyStore.getEntry(key, keyPassword);
	//			return ((KeyStore.SecretKeyEntry) entry).getSecretKey().getEncoded().length;
	//		} else {
	//			return Integer.valueOf(keySize);
	//		}
	//	}

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
		String ip = multicastIp.getHostAddress();
		if (!hasAccess(ip)) {
			throw new UnauthorizedException("Unauthorized to join " + ip);
		}
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

	public void requestAuthorization(String id, String password, InetAddress group)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
		if (id.getBytes(StandardCharsets.UTF_8).length > MAX_ID_BYTES) {
			throw new IllegalArgumentException("Id too long (max " + MAX_ID_BYTES + ")");
		}

		// Cliente > AS: Cliente ID || NonceC || IPMC || AutenticadorC
		// Cliente ID = id to cliente (username + email)
		// IPMC = endereço Multicast a que o cliente se quer juntar
		// NonceC = random number gerado pelo cliente
		// AutenticadorC = E [ kc, ( NonceC || IPMC || SHA-512(pwd) || MACk (X) ) ]
		// X = NonceC || IPMC || SHA-512(pwd)
		// Kc = SHA-512(pwd)
		// k = MD5 (NonceC || SHA-512(pwd))
		int nounce = generateNounce();
		byte[] multicastIpBytes = new String("<"+group.getHostAddress()+">").getBytes(StandardCharsets.UTF_8);
		MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
		String sha512PasswordHex = Utils.toHex(sha512.digest(password.getBytes(StandardCharsets.UTF_8)));
		byte[] sha512PasswordBytes = sha512PasswordHex.getBytes(StandardCharsets.UTF_8);
		System.out.println("SHA-512 password for client \"" + id + "\": " + sha512PasswordHex);
		// Content = NonceC || IPMC || SHA-512(pwd)
		ByteBuffer content = ByteBuffer
				.allocate(Integer.BYTES + 32 + sha512PasswordBytes.length) //TODO 32 for multicastip field
				.putInt(nounce)
				.put(multicastIpBytes)
				.put(sha512PasswordBytes);
		String macAlgorithm = getMacAlgorithm();
		Mac mac = Mac.getInstance(macAlgorithm);
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		byte[] md5Content = ByteBuffer
				.allocate(Integer.BYTES + sha512PasswordBytes.length)
				.putInt(nounce)
				.put(sha512PasswordBytes)
				.array();
		SecretKey macKey = new SecretKeySpec(md5.digest(md5Content), macAlgorithm);
		mac.init(macKey);
		byte[] contentMac = mac.doFinal(content.array());

		byte[] authenticatorContent = ByteBuffer
				.allocate(Integer.BYTES + 32 + sha512PasswordBytes.length + contentMac.length)
				.putInt(nounce)
				.put(multicastIpBytes)
				.put(sha512PasswordBytes)
				.put(contentMac)
				.array();

		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };
		int iterationCount = 2048;

		String pbeAlgorithm = getPBEAlgorithm();
		Cipher cipher = Cipher.getInstance(pbeAlgorithm);
		Key key = SecretKeyFactory.getInstance(pbeAlgorithm).generateSecret(new PBEKeySpec(sha512PasswordHex.toCharArray()));
		cipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount)); // TODO salt e itCount?
		byte[] authenticator = cipher.doFinal(authenticatorContent);

		byte[] clientIdBytes = ByteBuffer.allocate(MAX_ID_BYTES).put(new String("<"+id+">").getBytes(StandardCharsets.UTF_8)).array();

		byte[] request = ByteBuffer
				.allocate(MAX_ID_BYTES + Integer.BYTES + 32 + authenticator.length)
				.put(clientIdBytes)
				.putInt(nounce)
				.put(multicastIpBytes)
				.put(authenticator)
				.array();
		byte[] header = buildHeader(PayloadType.SAP, (short)request.length);
		byte[] message = ByteBuffer
				.allocate(header.length + request.length)
				.put(header)
				.put(request)
				.array();
		
		// Send message to AuthServer 
		DatagramPacket sendPacket = new DatagramPacket(message, message.length, InetAddress.getByName(AUTH_SERVER_IP), 3000); // TODO constantes do server
		setSoTimeout(5000); // TODO config file
		send(sendPacket);
		DatagramPacket recievePacket = new DatagramPacket(new byte[65536], 65536);
		setSoTimeout(10000); 
		// and recieve reply message
		receive(recievePacket);


		// Reply from server: E[KPBE, NonceC+1 || NonceS || TicketAS || MACK (X) ]
		// NonceC+1 = resposta ao desafio NonceC da ronda 1, por parte do servidor.
		// NonceS = nonce gerado pelo servidor
		// KBE = SHA-512(pwd) || NonceC+1
		// TicketAS = estrutura de dados que conterá todas as informações para permitir entrar e comunicar numa sessão segura multicast
		// K = MD5 (NonceC+1 || SHA-512(pwd))
		// X = NonceC+1 || NonceS || TicketAS
		String decryptPassword = Utils.toHex(
				ByteBuffer.allocate(sha512PasswordBytes.length + Integer.BYTES)
				.put(sha512PasswordBytes)
				.putInt(nounce + 1)
				.array());
		System.out.println("Decrypt password: " + decryptPassword);
		key = SecretKeyFactory.getInstance(pbeAlgorithm).generateSecret(new PBEKeySpec(decryptPassword.toCharArray()));
		cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
		ByteBuffer reply = ByteBuffer
				.allocate(cipher.getOutputSize(recievePacket.getLength()))
				.put(cipher.doFinal(recievePacket.getData()));
		int replySize = reply.array().length;
		int nounceCPlus1 = reply.getInt();
		if (nounce + 1 != nounceCPlus1) {
			throw new UserAuthenticationException(""); // TODO
		}
		int nounceS = reply.getInt();
		if (nounces.contains(nounceS)) {
			throw new DataReplyingException();
		}
		byte[] ticketBytes = new byte[1024];
		reply.get(ticketBytes, Integer.BYTES + Integer.BYTES, ticketBytes.length);
		ByteArrayInputStream bis = new ByteArrayInputStream(ticketBytes);
		ObjectInput in = new ObjectInputStream(bis);
		TicketAS ticket = (TicketAS)in.readObject(); 
		md5Content = ByteBuffer
				.allocate(Integer.BYTES + sha512PasswordBytes.length)
				.putInt(nounce+1)
				.put(sha512PasswordBytes)
				.array();
		macKey = new SecretKeySpec(md5.digest(md5Content), macAlgorithm);
		mac.init(macKey);
		byte[] messageHash = Arrays.copyOfRange(reply.array(), reply.arrayOffset(), replySize);
		if (MessageDigest.isEqual(mac.doFinal(contentMac), messageHash)) {
			throw new DataIntegrityAuthenticityException("Macs do not match");
		}
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



	//	
	//	ByteArrayInputStream bis = new ByteArrayInputStream(yourBytes);
	//	ObjectInput in = null;
	//	try {
	//	  in = new ObjectInputStream(bis);
	//	  Object o = in.readObject(); 
	//	  ...
	//	} finally {
	//	  try {
	//	    if (in != null) {
	//	      in.close();
	//	    }
	//	  } catch (IOException ex) {
	//	    // ignore close exception
	//	  }
	//	}

}
