package testMulticast;

import java.net.*;
import java.io.*;
import java.util.*;

public class MulticastReceiver {

    public static void main(String[] args ) throws Exception {
	    if( args.length != 2 ) {
		System.err.println("usage: java MulticastReceiver grupo_multicast porto") ;
		System.exit(0) ;
	    }
 
    int port = Integer.parseInt( args[1]) ;
    InetAddress group = InetAddress.getByName( args[0] ) ;

    if( !group.isMulticastAddress() ) {
	System.err.println("Multicast address required...") ;
	System.exit(0) ;
    }

    MulticastSocket rs = new MulticastSocket(port) ;

    rs.joinGroup(group);

    DatagramPacket p = new DatagramPacket( new byte[65536], 65536 ) ;
    String recvmsg;

    do {

        p.setLength(65536); // resize with max size
	rs.receive(p) ;
        recvmsg =  new String( p.getData(), 0, p.getLength() ) ;
        
	System.out.println("Msg recebida: "+ recvmsg  ) ;
    } while(!recvmsg.equals("fim")) ;

    // rs.leave if you want leave from the multicast group ...
    rs.close();
	    
    }
}
