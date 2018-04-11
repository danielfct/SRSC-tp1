package stgc;

public class Header {

	private byte versionRelease;
	private char payloadType;
	private short payloadSize;
	
	public Header(byte versionRelease, char payloadType, short payloadSize) {
		this.versionRelease = versionRelease;
		this.payloadType = payloadType;
		this.payloadSize = payloadSize;
	}
	
	public void setVersionRelease(byte versionRelease) {
		this.versionRelease = versionRelease;
	}
	
	public void setPayloadType(char payloadType) {
		this.payloadType = payloadType;
	}
	
	public void setPayloadSize(short payloadSize) {
		this.payloadSize = payloadSize;
	}	
	
	public byte getVersionRelease() {
		return versionRelease;
	}
	
	public int getVersion() {
		String versionBinary = getVersionReleaseBinary().substring(0, 4);
		return Integer.parseInt(versionBinary, 2);
	}
	
	public int getRelease() {
		String releaseBinary = getVersionReleaseBinary().substring(0, 4);
		return Integer.parseInt(releaseBinary, 2);
	}
	
	private String getVersionReleaseBinary() {
		byte versionRelease = getVersionRelease();
		String versionReleaseBinary = Integer.toBinaryString((int)versionRelease);
		return String.format("%8s", versionReleaseBinary).replace(' ', '0'); 
	}
	
	public char getPayloadType() {
		return payloadType;
	}
	
	public short getPayloadSize() {
		return payloadSize;
	}

}
