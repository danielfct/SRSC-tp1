package stgc;

import java.io.Serializable;
import java.net.InetAddress;

public class TicketAS implements Serializable {
	//
	//	<224.10.10.10>
	//	ciphersuite = AES/CBC/PKCS5Padding
	//	keysize = *
	//	keyvalue = *
	//	mac = HmacSHA256
	//	mackeysize = *
	//	mackeyvalue = *
	//</224.10.10.10>

	private InetAddress group;
	private String ciphersuite;
	private int keySize;
	private String keyValue;
	private String mac;
	private int macKeySize;
	private String macKeyValue;

	@Override
	public String toString() {
		 // TODO
		return "";
	}

}