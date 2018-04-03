package mchat;

import java.io.*;

public class IPPortExample {
	
  public static void main( String args[]) throws Exception {
	  BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	  for ( ; ; ) {
		  IPPort ipport = IPPort.generateNew();
		  System.out.println("IP = " + ipport.ip + " ; port = " + ipport.port);
		  System.out.print("0 para sair >");
		  System.out.flush();
		  if (reader.readLine().equals("0"))
			  break;
	  }
  }
  
}

