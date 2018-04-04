package stgc_tlp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64;
import stgc_tlp.Ciphersuite;

public final class STGCMulticastSocket extends MulticastSocket {

	private static final int VERSION = 1;
	private static final int RELEASE = 1;
	private static final byte SEPARATOR = 0x00;
	private static final String JCEKS_VALUE = "*";

	enum PayloadType {
		MESSAGE('M'), SAP('S');
		public final char code;
		PayloadType(char code) {
			this.code = code;
		}
	}

	public STGCMulticastSocket(SocketAddress paramSocketAddress) throws IOException {
		super(paramSocketAddress);
	}

	public STGCMulticastSocket(int paramInt) throws IOException {
		super(paramInt);
	}

	public STGCMulticastSocket() throws IOException {
		super();
	}

	@Override
	public void send(DatagramPacket datagramPacket) throws IOException {
		this.send(datagramPacket, PayloadType.MESSAGE);
	}

	private void send(DatagramPacket datagramPacket, PayloadType payloadType) throws IOException {
		byte[] data = buildProtectedMessage(datagramPacket.getData(), payloadType, (short)datagramPacket.getLength());
		System.out.println(new String(data));
		datagramPacket.setData(data);
		super.send(datagramPacket);
	}

	@Override
	public synchronized void receive(DatagramPacket paramDatagramPacket) throws IOException {
		//TODO
		super.receive(paramDatagramPacket);
	}

	private byte[] buildProtectedMessage(byte[] data, PayloadType payloadType, short payloadSize) {
		byte[] header = buildHeader(payloadType, payloadSize);
		byte[] payload = buildPayload();
		byte[] message = null; // TODO
		return message;
	}

	private byte[] buildHeader(PayloadType payloadType, short payloadSize) {
		return ByteBuffer
				.allocate(6)
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

	private byte[] buildPayload() throws Exception {
		//PAYLOAD = E (KS, [ Mp || MACKM (Mp) ]) || MACKA (C)
		
		String ciphersuite = getPropertyValue("ciphersuite");
		// TODO provedor?
		SecretKey ks = getKs();
		byte[] mp
		
		
		return null;
	}

	private String getPropertyValue(String propertyKey) throws IOException {
		InputStream is = new FileInputStream("cipherSuite.conf");
		Properties properties = new Properties();
		properties.load(is);
		return properties.getProperty(propertyKey);
	}

	private SecretKey getKs() throws Exception {
		SecretKey ks = null;
		String keyValue = getPropertyValue("keyvalue");
		if (!keyValue.equals(JCEKS_VALUE)) {
			Ciphersuite cs = new Ciphersuite(getPropertyValue("ciphersuite"));
			ks = new SecretKeySpec(keyValue.getBytes(), cs.getAlgorithm());
		} else {
			final String keyStoreFile = "mykeystore.jceks"; //TODO constante global
			KeyStore keyStore = getKeyStore(keyStoreFile, "password");
			PasswordProtection keyPassword = new PasswordProtection("password".toCharArray());
			KeyStore.Entry entry = keyStore.getEntry("ks", keyPassword);
			ks = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
		}
		return ks;
	}
	
	private KeyStore getKeyStore(String fileName, String pw) throws Exception {
		File file = new File(fileName);
		final KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(file), pw.toCharArray());
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
