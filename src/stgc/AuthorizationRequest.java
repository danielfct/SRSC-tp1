package stgc;

class AuthorizationRequest {

	private byte[] payload;
	private int nounce;
	
	public AuthorizationRequest(byte[] payload, int nounce) {
		this.payload = payload;
		this.nounce = nounce;
	}
	
	public byte[] getPayload() {
		return payload;
	}
	
	public int getNounce() {
		return nounce;
	}
	
	public void setPayload(byte[] payload) {
		this.payload = payload;
	}
	
	public void setNounce(int nounce) {
		this.nounce = nounce;
	}
	
}
