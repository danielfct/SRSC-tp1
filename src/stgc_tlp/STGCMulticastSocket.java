package stgc_tlp;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.net.SocketAddress;

public final class STGCMulticastSocket extends MulticastSocket {

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
	public void send(DatagramPacket paramDatagramPacket) throws IOException {
		//TODO
		super.send(paramDatagramPacket);
	}
	
	@Override
	 public synchronized void receive(DatagramPacket paramDatagramPacket) throws IOException {
		//TODO
		super.receive(paramDatagramPacket);
	}
	
}
