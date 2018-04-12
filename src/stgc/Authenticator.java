package stgc;

import java.io.Serializable;

class Authenticator implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private int nounce;
	private String ip;
	private String digestedPassword;
	
	public Authenticator(int nounce, String ip, String digestedPassword) {
		this.nounce = nounce;
		this.ip = ip;
		this.digestedPassword = digestedPassword;
	}
	
	public int getNounce() {
		return nounce;
	}
	
	public String getIp() {
		return ip;
	}
	
	public String getDigestedPassword() {
		return digestedPassword;
	}
	
	public void setNounce(int nounce) {
		this.nounce = nounce;
	}
	
	public void setIp(String ip) {
		this.ip = ip;
	}
	
	public void setDigestPassword(String digestedPassword) {
		this.digestedPassword = digestedPassword;
	}

	@Override
	public String toString() {
		return "Authenticator [nounce=" + nounce + ", ip=" + ip + ", digestedPassword=" + digestedPassword + "]";
	}
	
}
