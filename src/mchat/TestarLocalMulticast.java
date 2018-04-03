package mchat;

// TestarLocalMulticast.java
// Apenas para testar

import java.net.*;

public class TestarLocalMulticast {

	public static void main(String[] args) throws UnknownHostException, SocketException, java.io.IOException {
		int port = 5265; 
		// O end. multicast vai ser colocado hard-coded
		InetAddress group = InetAddress.getByName("224.10.10.10");
		// create datagram socket
		System.out.println("Binding do socket ao grupo multicast " + group.getHostAddress() + ":" + port + " ...");
		MulticastSocket msocket = new MulticastSocket(port);
		msocket.setSoTimeout(10000);
		msocket.setTimeToLive(1);  // restringir entregas a rede local
		// join ao grupo multicast 
		System.out.println("Juncao ao grupo multicast ...");
		msocket.joinGroup(group);
		// criar datagrama a enviar e colocar o end. destino do proprio
		String outMessage = "Mensagem multicast... Hello!";
		byte[] data = outMessage.getBytes();
		DatagramPacket packet = new DatagramPacket(data, data.length, group, port);
		// send datagram (to ourself)
		System.out.println("Enviar mensagem em multicast: " + outMessage);
		msocket.send(packet);
		// preparar para receber o datagrama
		packet.setData(new byte[512]);
		packet.setLength(512); // importante o tamanho para receber !
		// receive datagram (may time out)
		System.out.println("Estou a espera de datagramas multicast ...");
		msocket.receive(packet);
		// Mostrar resultado
		String inMessage = new String(packet.getData(), 0, packet.getLength());
		System.out.println("Recebi mensagem multicast - conteudo: " + inMessage);
		// Abandonar o grupo multicast
		System.out.println("Vou sair do grupo multicast...");
		msocket.leaveGroup(group);
		msocket.close();
	}
}
