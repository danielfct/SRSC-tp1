package stgc_tlp;

public enum PayloadType {

	MESSAGE('M'), SAP('S');

	public final char code;

	PayloadType(char code) {
		this.code = code;
	}
}
