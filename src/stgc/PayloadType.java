package stgc;

enum PayloadType {

	MESSAGE('M'), SAP_AUTH_REQUEST('A'), SAP_AUTH_REPLY('R');

	public final char code;

	PayloadType(char code) {
		this.code = code;
	}
}
