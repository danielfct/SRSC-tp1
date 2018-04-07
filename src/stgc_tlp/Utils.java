package stgc_tlp;

public class Utils {

	private static String digits = "0123456789abcdef";
	
	public static String toHex(byte[] data, int length) {
		StringBuffer buf = new StringBuffer();
		for (byte b : data) {
			int	v = b & 0xff;
			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}
		return buf.toString();
	}

	public static String toHex(byte[] data) {
		return toHex(data, data.length);
	}
	
	public static String toHex(int ch) {
		return String.format("%04x", (int) ch);
	}
	
}
