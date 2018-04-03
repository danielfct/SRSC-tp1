package mchat;

public class IPPort {
	
	public String ip;
	public int port;

	private static final int SEED = 45404;	// DEVE SER INICIADA COM O NUMERO DE ALUNO
	
	private static int lastPort = 3000;		// Porto inicial
	private static String IPprefix = "225.";
	private static int n1 = SEED / 256;
	private static int n2 = SEED % 256;
	private static int n3 = 1;
	
	public static IPPort generateWellKnown() {
		String ip = IPprefix + SEED / 256 + "." + SEED % 256 + ".0";
		return new IPPort( ip, 2345);
	}

	public static IPPort generateNew() {
		String ip = IPprefix + n1 + "." + n2 + "." + n3;
		n3++;
		if (n3 > 255) {
			n3 = 0;
			n2++;
			if (n2 > 255) {
				n2 = 0;
				n1++;
			}
		}
		return new IPPort(ip, ++lastPort);
	}

	protected IPPort(String ip, int port) {
		this.ip = ip;
		this.port = port;
	}

}