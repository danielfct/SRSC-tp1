package stgc_tlp;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry.Attribute;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import stgc_tlp.Ciphersuite;
import stgc_tlp.data_structures.LimitedSizeQueue;
import stgc_tlp.exceptions.DenialOfServiceException;
import stgc_tlp.exceptions.DataIntegrityAuthenticityException;
import stgc_tlp.exceptions.DataReplyingException;

public final class STGCMulticastSocket extends MulticastSocket {

	private static final int VERSION = 1;
	private static final int RELEASE = 1;
	private static final byte SEPARATOR = 0x00;
	private static final String JCEKS_VALUE = "*";
	private static final int HEADER_SIZE = 6;
	private static final int MAX_NOUNCES = 100;

	private List<Integer> nounces;

	// TODO class para isto
	enum PayloadType {

		MESSAGE('M'), SAP('S');

		public final char code;

		PayloadType(char code) {
			this.code = code;
		}
	}

	public STGCMulticastSocket(SocketAddress paramSocketAddress) throws IOException {
		super(paramSocketAddress);
		this.nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);
	}

	public STGCMulticastSocket(int paramInt) throws IOException {
		super(paramInt);
		this.nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);
	}

	public STGCMulticastSocket() throws IOException {
		super();
		this.nounces = new LimitedSizeQueue<Integer>(MAX_NOUNCES);

	}

	@Override
	public void send(DatagramPacket datagramPacket) throws IOException {
		this.send(datagramPacket, PayloadType.MESSAGE);
	}

	private void send(DatagramPacket datagramPacket, PayloadType payloadType) throws IOException {
		try {
			byte[] data = buildProtectedMessage(datagramPacket.getData(), payloadType);
			datagramPacket.setData(data);
			super.send(datagramPacket);
		} catch (Exception e) {
			e.printStackTrace();
		}	
	}

	@Override
	public synchronized void receive(DatagramPacket datagramPacket) throws IOException {
		super.receive(datagramPacket);
		//System.out.println(new String(datagramPacket.getData(), 0, datagramPacket.getLength()));

		try {
			decryptProtectedMessage(datagramPacket);
		} catch (InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| UnrecoverableEntryException | NoSuchPaddingException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

	}

	private byte[] buildProtectedMessage(byte[] data, PayloadType payloadType) 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, 
			NoSuchPaddingException, KeyStoreException, CertificateException, 
			UnrecoverableEntryException, ShortBufferException, IllegalBlockSizeException, 
			BadPaddingException, IllegalStateException, NoSuchProviderException, InvalidAlgorithmParameterException {
		byte[] payload = buildPayload(data);
		byte[] header = buildHeader(payloadType, (short)payload.length);
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
		//System.out.println("Version-Release: " + VERSION + "." + RELEASE);
		String versionBinary = intTo4Bits(VERSION);
		String releaseBinary = intTo4Bits(RELEASE);
		String versionReleaseBinary = versionBinary + releaseBinary;
		//System.out.println("Version-Release Bin: " + versionReleaseBinary);
		int versionReleaseDecimal = Integer.parseInt(versionReleaseBinary, 2);
		String versionReleaseHex = String.format("%02X", versionReleaseDecimal);
		//System.out.println("Version-Release Hex: " + versionReleaseHex);
		byte versionReleaseByte = (byte) ((Character.digit(versionReleaseHex.charAt(0), 16) << 4) + Character.digit(versionReleaseHex.charAt(1), 16));
		//System.out.println("Version-Release Byte: " + versionReleaseByte);
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
	
		Ciphersuite cs = new Ciphersuite(getPropertyValue("ciphersuite"));
		Cipher cipher = Cipher.getInstance(cs.getTransformation()); // TODO provider?
		String macAlgorithm = getPropertyValue("mac");
		// Cifrar Mp e MacKm (Mp) com a chave Ks

		SecretKey sessionKey = getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv(16)); //TODO
		Mac mac = Mac.getInstance(getPropertyValue("mac"));
		byte[] macKeys = buildMacKeys();
		SecretKey personalMessageMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, 0, macKeys.length/2), macAlgorithm);
		SecretKey contentMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, macKeys.length/2, macKeys.length), macAlgorithm);
		//System.out.println("Pm Mac key: " + personalMessageMacKey.getEncoded().length + " " + Utils.toHex(personalMessageMacKey.getEncoded(), personalMessageMacKey.getEncoded().length));
		//System.out.println("C Mac key: " + contentMacKey.getEncoded().length + " " + Utils.toHex(contentMacKey.getEncoded(), contentMacKey.getEncoded().length));
		byte[] personalMessage = getPersonalMessage(data);

		// Parte da cifra
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
		byte[] content = new byte[cipher.getOutputSize(personalMessage.length + mac.getMacLength())];
		int contentLength = cipher.update(personalMessage, 0, personalMessage.length, content, 0);

		// Parte do MacKm (Mp)
		mac.init(personalMessageMacKey);
		mac.update(personalMessage);
		cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), content, contentLength);

		// Parte do MacKa (C)
		mac.init(contentMacKey);
		mac.update(content);
		byte[] payload = ByteBuffer.allocate(content.length + mac.getMacLength()).put(content).array();
		mac.doFinal(payload, content.length);
		//System.out.println("Content: " + content.length + " " + Utils.toHex(content, content.length));
		//System.out.println("Payload: " + payload.length + " " + Utils.toHex(payload, payload.length));
		
		return payload;
	}
	
	private void decryptProtectedMessage(DatagramPacket datagramPacket) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
			UnrecoverableEntryException, IOException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException, 
			IllegalBlockSizeException, BadPaddingException {
		byte[] data = datagramPacket.getData();
		ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE).put(data, 0, HEADER_SIZE);
		byte versionRelease = header.get(0);
		//header.get(1); // separator
		char payloadType = (char)header.get(2);
		//header.get(3); // separator
		short payloadSize = header.getShort(4);
		byte[] payload = ByteBuffer.allocate(payloadSize).put(data, HEADER_SIZE, payloadSize).array();
		
		SecretKey sessionKey = getSessionKey();
		IvParameterSpec ivSpec = new IvParameterSpec(createIv(16));

		String macAlgorithm = getPropertyValue("mac");
		Mac mac = Mac.getInstance(macAlgorithm);
		byte[] macKeys = buildMacKeys();
		SecretKey personalMessageMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, 0, macKeys.length/2), macAlgorithm);
		SecretKey contentMacKey = new SecretKeySpec(Arrays.copyOfRange(macKeys, macKeys.length/2, macKeys.length), macAlgorithm);
		//System.out.println("Pm Mac key: " + personalMessageMacKey.getEncoded().length + " " + Utils.toHex(personalMessageMacKey.getEncoded(), personalMessageMacKey.getEncoded().length));
		//System.out.println("C Mac key: " + contentMacKey.getEncoded().length + " " + Utils.toHex(contentMacKey.getEncoded(), contentMacKey.getEncoded().length));
		
		// Verificação Mac do conteudo para evitar ataques de disponibilidade
		mac.init(contentMacKey);
		final int contentMacSize = mac.getMacLength();
		final int contentSize = payloadSize - contentMacSize;
		mac.update(payload, 0, contentSize);
		if (!MessageDigest.isEqual(mac.doFinal(), Arrays.copyOfRange(payload, contentSize, payloadSize))) {
			throw new DenialOfServiceException("Content MAC does not match.");
		}
		
		//byte[] contentHash = ByteBuffer.allocate(contentMacSize).put(payload, contentSize, contentMacSize).array();
		//byte[] f = mac.doFinal();	
		//byte[] c = ByteBuffer.allocate(contentSize).put(payload, 0, contentSize).array();
		//System.out.println("Content: " + c.length + " " + Utils.toHex(c, c.length));
		//System.out.println("Payload: " + payloadSize + " " + Utils.toHex(payload, payloadSize));
		//System.out.println("Content Hash: " + contentHash.length + " " + Utils.toHex(contentHash, contentHash.length));
		//System.out.println("Hashed: " + f.length + " " + Utils.toHex(f, f.length));

		// Decifra o conteúdo
		Cipher cipher = Cipher.getInstance(getPropertyValue("ciphersuite"));
		cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
		byte[] content = cipher.doFinal(payload, 0, contentSize);
		final int messageMacLength = mac.getMacLength();
		final int personalMessageLength = content.length - messageMacLength;
		final int messageLength = personalMessageLength - Integer.BYTES; // - size of id
		ByteBuffer personalMessage = ByteBuffer.allocate(personalMessageLength).put(content, 0, personalMessageLength);
		// Verificar o nounce para evitar a repetição de mensagens
		int nounce = personalMessage.getInt(0);
		if (nounces.contains(nounce)) {
			throw new DataReplyingException();
		}
		nounces.add(nounce);
		// Verificacao Mac
		mac.init(personalMessageMacKey);
		mac.update(content, 0, personalMessageLength);
		byte[] messageHash = ByteBuffer.allocate(messageMacLength).put(content, personalMessageLength, messageMacLength).array();
		if (!MessageDigest.isEqual(mac.doFinal(), messageHash)) {
			throw new DataIntegrityAuthenticityException("Message Mac does not match.");
		}
		// Obter a mensagem inicial
		byte[] message = ByteBuffer.allocate(data.length).put(personalMessage.array(), Integer.BYTES, messageLength).array();
		datagramPacket.setData(message, 0, messageLength);
	}

	private byte[] buildMacKeys() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableEntryException, IOException {
		byte[] macKey = null;
		String macKeyValue = getPropertyValue("mackeyvalue");
		if (!macKeyValue.equals(JCEKS_VALUE)) {
			macKey = macKeyValue.getBytes();
		} 
		else {
			macKey = getKeyStore("src/mykeystore.jceks", "password").getKey("mackey", "password".toCharArray()).getEncoded();
		}
		return MessageDigest.getInstance("SHA-256").digest(macKey);
	}

	private String getPropertyValue(String propertyKey) throws IOException {
		InputStream is = new FileInputStream("src/ciphersuite.conf");
		Properties properties = new Properties();
		properties.load(is);
		return properties.getProperty(propertyKey);
	}

	private int getKeySize(String key, String password) 
			throws KeyStoreException, NoSuchAlgorithmException, 
			CertificateException, IOException, 
			UnrecoverableEntryException {
		String keySize = getPropertyValue("keysize");
		if (keySize.equals(JCEKS_VALUE)) {
			final String keyStoreFile = "src/mykeystore.jceks"; //TODO constante global
			KeyStore keyStore = getKeyStore(keyStoreFile, "password"); //TODO change password
			PasswordProtection keyPassword = new PasswordProtection(password.toCharArray());
			KeyStore.Entry entry = keyStore.getEntry(key, keyPassword);
			return ((KeyStore.SecretKeyEntry) entry).getSecretKey().getEncoded().length;
		} else {
			return Integer.valueOf(keySize);
		}

	}

	private SecretKey getSessionKey() 
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
		SecretKey sessionKey = null;
		String keyValue = getPropertyValue("keyvalue");
		if (!keyValue.equals(JCEKS_VALUE)) {
			Ciphersuite cs = new Ciphersuite(getPropertyValue("ciphersuite"));
			sessionKey = new SecretKeySpec(keyValue.getBytes(), cs.getAlgorithm()); 
		} else {
			final String keyStoreFile = "src/mykeystore.jceks"; //TODO constante global
			KeyStore keyStore = getKeyStore(keyStoreFile, "password"); //TODO change password
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
				//.put(id.getBytes())
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


	/*

	M’ = HEADER || PAYLOAD

	HEADER = VERSION-RELEASE || 0x00 || PAYLOAD_TYPE || 0x00 || PAYLOAD_SIZE

	Version-Release: 1 byte (4 bits VERSION + 4 bits RELEASE) Ex: 1.1 : 00010001

	0x00 byte usado como separador

	PAYLOAD_TYPE: 1 byte, ex:
		M: indica que payload contem mensagem de dados de aplicação
		S: indica que payload contem uma mensagem STGC-SL

	PAYLOAD_SIZE: 2 bytes (ou short integer) contendo o tamanho do Payload transportado

	PAYLOAD representa a carga da mensagem STGC que depende do PAYLOAD_TYPE

	PAYLOAD-TYPE = M: Payload representa dados (bytes) de uma aplicação (ou seja,
	codificando as mensagens de um protocolo do nível aplicação)
	PAYLOAD-TYPE = S: Payload representa dados (bytes) para processamento segundo o
	subprotocolo STGC-SL.

	Em todo o caso, o PAYLOAD é codificado com suporte criptográfico da seguinte forma:
	PAYLOAD = E (KS, [ Mp || MACKM (Mp) ] || MACKA (C)
	Sendo:
	Mp = [id || nonce || M]
	C = E (KS, [ Mp || MACKM (Mp) ]
	Ks: chave de sessão (sessão de grupo multicast segura STGC)
	KM: Chave de autenticidade e integridade na função MAC
	KA: Chave de controlo para mitigação de ataques contra a disponibilidade

	 */

}
