package stgc_sap;

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

import stgc_tlp.PayloadType;
import stgc_tlp.STGCMulticastSocket;
import stgc_tlp.data_structures.LimitedSizeQueue;
import stgc_tlp.exceptions.DataIntegrityAuthenticityException;
import stgc_tlp.exceptions.DataReplyingException;
import stgc_tlp.exceptions.UserAuthenticationException;
import stgc_tlp.exceptions.UserUnregisteredException;
import utils.Utils;

public class AuthenticationServer {

	private static final String DACL_FILE = "res/dacl.conf";
	private static final String USERS_FILE = "res/users.conf";
	private static final String CIPHERSUITE_FILE = "res/ciphersuite.conf";
	private static final String KEYSTORE_FILE = "res/keystore.jceks";
	public static final int MAX_NOUNCES = 100;
	
	// TODO
	public static final int VERSION = 1;
	public static final int RELEASE = 1;
	public static final byte SEPARATOR = 0x00;
	public static final String JCEKS_VALUE = "*";
	public static final int PACKET_HEADER_SIZE = 6;
	public static final String PROVIDER = "BC";
	public static final int MAX_ID_BYTES = 10 + 256; // 10 chars (nickname) + 256 chars (email)

	private static final String AUTH_SERVER_IP = "224.10.10.10";

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
				socket.receive(inPacket);
				System.out.println("> Recieved auth request at " + new Date());
				byte[] data = inPacket.getData();
				// Cliente > AS: Cliente ID || NonceC || IPMC || AutenticadorC
				// IPMC = endereço Multicast a que o cliente se quer juntar
				// NonceC = random number gerado pelo cliente
				// AutenticadorC = E [ kc, ( NonceC || IPMC || SHA-512(pwd) || MACk (X) ) ]
				// X = NonceC || IPMC || SHA-512(pwd)
				// Kc = SHA-512(pwd)
				// k = MD5 (NonceC || SHA-512(pwd))

				// Client || Nounce || IP || E( k1, [Nounce || IP || SHA-512(pwd) || MAC k2[Nounce || IP || SHA-512(pwd)]) 
				// k1 = SHA-512(pwd)
				// k2 = MD5 (NonceC || SHA-512(pwd))

				ByteBuffer dataBuffer = ByteBuffer.wrap(data); //TODO read only
				// HEADER
				byte versionRelease = dataBuffer.get();
				dataBuffer.position(dataBuffer.position() + 1); // skip separator
				char payloadType = (char)dataBuffer.get();	
				if (payloadType != PayloadType.SAP.code) {
					throw new Exception(); // TODO
				}
				dataBuffer.position(dataBuffer.position() + 1); // skip separator
				short payloadSize = dataBuffer.getShort();
				// PAYLOAD
				int messageHeaderSize = MAX_ID_BYTES + Integer.BYTES + 32; // 10+256 bytes para clientid, 32 bytes para ip
				int authSize = payloadSize - messageHeaderSize;

				byte[] clientId = new byte[MAX_ID_BYTES];
				dataBuffer.get(clientId);
				String client = Utils.subStringBetween(new String(clientId), '<', '>'); // client
				System.out.println(client);
				int nounceC = dataBuffer.getInt(); // nounce
				if (nounces.contains(nounceC)) {
					throw new DataReplyingException();
				}
				nounces.add(nounceC);
				byte[] multicastIp = new byte[32];			
				dataBuffer.get(multicastIp);
				String ip = Utils.subStringBetween(new String(multicastIp), '<', '>');
				System.out.println(ip); // ip
				if (!isRegistered(ip, client)) {
					throw new UserUnregisteredException("User \"" + client + "\" is not registered at ip: " + ip);
				}

				ByteBuffer authenticator = ByteBuffer.allocate(authSize).put(data, messageHeaderSize, authSize);
				String pbeAlgorithm = getPBEAlgorithm();
				Cipher cipher = Cipher.getInstance(pbeAlgorithm,"BC");
				String hashedPassword = getPropertyValue("users.conf", client);
				char[] passwordSeed = hashedPassword.toCharArray(); // k1
				Key key = SecretKeyFactory.getInstance(pbeAlgorithm).generateSecret(new PBEKeySpec(passwordSeed));
				byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; // TODO
				int iterationCount = 2048; // TODO
				cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
				byte[] out = cipher.doFinal(authenticator.array());
				ByteBuffer auth = ByteBuffer.allocate(out.length).put(out);
				int nounceCiphered = auth.getInt(); // nounceC
				byte[] multicastIpCiphered = new byte[32]; // ipC
				auth.get(multicastIpCiphered);
				byte[] passwordCiphered = new byte[passwordSeed.length * Character.BYTES]; // sha512(pwd)C
				System.out.println("passC length " + passwordCiphered.length);
				auth.get(passwordCiphered);

				if (nounceC != nounceCiphered || !ip.equals(new String(multicastIpCiphered)) || !hashedPassword.equalsIgnoreCase(new String(passwordCiphered))) {
					throw new UserAuthenticationException("Unable to authenticate user \"" + client + "\".");
				}

				ByteBuffer macContent = ByteBuffer
						.allocate(Integer.BYTES + multicastIp.length + passwordSeed.length)
						.putInt(nounceC)
						.put(multicastIp)
						.put(hashedPassword.getBytes(StandardCharsets.UTF_8));
				String macAlgorithm = getMacAlgorithm();
				Mac mac = Mac.getInstance(macAlgorithm);
				// k2
				byte[] macKeySeed = MessageDigest.getInstance("MD5").digest(ByteBuffer.allocate(Integer.BYTES + passwordSeed.length).putInt(nounceC).put(hashedPassword.getBytes(StandardCharsets.UTF_8)).array());
				SecretKey macKey = new SecretKeySpec(macKeySeed, macAlgorithm);
				mac.init(macKey);
				byte[] macValue = new byte[mac.getMacLength()];
				auth.get(macValue);
				if (!MessageDigest.isEqual(macValue, mac.doFinal(macContent.array()))) {
					throw new DataIntegrityAuthenticityException("Macs do not match.");
				}


				// send reply

				// E[KPBE, ( NonceC+1 || NonceS || TicketAS ) || MACK (X) ]

				// NonceC+1 é a resposta ao desafio NonceC da ronda 1, por parte do servidor.
				// NonceS é um nonce gerado pelo servidor
				// A mensagem vai cifrada usando uma cifra do tipo password-based encryption, em que
				// A password-seed usada corresponde a: SHA-512(pwd) || NonceC+1
				// TicketAS será uma estrutura de dados que (deverá ser especificada e implementada por
				// cada grupo) e que conterá todas as informações que severão ser enviadas de forma /
				// segura e que permitem ao cliente ter todas as parametrizações criptográficas que
				// Permitirão entrar numa sessão segura multicast, nomeadamente, os dados
				// sobre a configuração da ciphersuite (no ficheiro ciphersuite.conf)
				// bem como das chaves KS e KM que se destinam a ser usadas na sessão (keystore.jecks)
				// A chave para o MAC pode ser a mesma como derivada na ronda 1, podendo X ser o conteúdo da primeira parte
				// da mensagem cifrada

				int nouncePlus1 = nounceC + 1;
				int nounceS = generateNounce();
				TicketAS ticket = new TicketAS(); // TODO
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ObjectOutput o = new ObjectOutputStream(bos);   
				o.writeObject(ticket);
				o.flush();
				byte[] ticketBytes = bos.toByteArray();
				// TODO definir ticket size


				// Colocar um MacK(X) no final da mensagem
				// K = MD5 (NonceC+1 || SHA-512(pwd))
				// X =  ( NonceC+1 || NonceS || TicketAS )
				byte[] md5Content = ByteBuffer
						.allocate(Integer.BYTES + hashedPassword.length())
						.putInt(nouncePlus1)
						.put(hashedPassword.getBytes(StandardCharsets.UTF_8))
						.array();
				macKey = new SecretKeySpec(MessageDigest.getInstance("MD5").digest(md5Content), "HmacSHA256");
				mac.init(macKey);
				byte[] contentMac = ByteBuffer
						.allocate(Integer.BYTES + Integer.BYTES + 1024)
						.putInt(nouncePlus1)
						.putInt(nounceS)
						.put(ticketBytes)
						.array();
				mac.update(contentMac);

				byte[] contentToCipher = ByteBuffer
						.allocate(Integer.BYTES + Integer.BYTES + ticketBytes.length + mac.getMacLength())
						.putInt(nouncePlus1)
						.putInt(nounceS)
						.put(ticketBytes)
						.array();

				mac.doFinal(contentToCipher, Integer.BYTES + Integer.BYTES + ticketBytes.length);

				// passwordSeed = SHA-512(pwd) || NonceC+1
				passwordSeed = new String(
						ByteBuffer
						.allocate(hashedPassword.length() + Integer.BYTES)
						.put(hashedPassword.getBytes(StandardCharsets.UTF_8))
						.putInt(nouncePlus1)
						.array()).toCharArray();
				key = SecretKeyFactory.getInstance(pbeAlgorithm).generateSecret(new PBEKeySpec(passwordSeed));
				cipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount)); // TODO salt e itCount?
				byte[] reply = cipher.doFinal(contentToCipher);

				socket.send(new DatagramPacket(reply, 0, reply.length, inPacket.getAddress(), inPacket.getPort()));	

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static int generateNounce() {
		SecureRandom random = new SecureRandom();
		int nounce = random.nextInt();
		return nounce;
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
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[0];
	}

	private static String getMacAlgorithm() throws IOException {
		String pbeAndMac = getPropertyValue("res/stgcsap.auth", "STGC-SAP");
		return pbeAndMac.split(":")[1];
	}


}
