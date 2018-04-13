package testMulticast;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import stgc.STGCMulticastSocket;

public class MulticastSender {

	public static void main(String[] args ) throws Exception {
		if (args.length != 3 ) {
			System.err.println("usage: java MulticastSender grupo_multicast porto time-interval") ;
			System.exit(0);
		}
		int more = 1000000;
		int port = Integer.parseInt(args[1]);
		InetAddress group = InetAddress.getByName(args[0]);
		int timeinterval = Integer.parseInt(args[2]);
		String msg;
		if (!group.isMulticastAddress()) {
			System.err.println("Multicast address required...");
			System.exit(0);
		}
		STGCMulticastSocket ms = new STGCMulticastSocket();
		ms.setSoTimeout(10000);
		ms.requestAuthorization("maria/maria@hotmail.com", "password", group);
		do {
			msg = "<maria/maria@hotmail.com>top secret message, sent on: " + new Date();
			byte[] data = msg.getBytes(StandardCharsets.UTF_8);
			DatagramPacket p = new DatagramPacket(data, data.length, group, port);
			ms.send(p);
			System.out.println("Tamanho: " + p.getLength() + "; Msg enviada: "+ msg);
			--more; 
			try {
				Thread.sleep(1000 * timeinterval);
			}
			catch (InterruptedException e) { }
		} while (more > 0);
		msg = "fim!";
		DatagramPacket p = new DatagramPacket(msg.getBytes(), msg.getBytes().length, group, port);
		ms.send(p);
		System.out.println("Tamanho: " + p.getLength() + "; Msg enviada: "+ msg);
		ms.close();
	}
}

