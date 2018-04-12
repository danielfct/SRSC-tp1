package stgc;

import java.io.Serializable;

class AuthorizationRequest implements Serializable {

	private static final long serialVersionUID = -7546180382410144525L;

	private String id;
	private int nounce;
	private String ip;
	private Authenticator auth;

	public AuthorizationRequest(String id, int nounce, String ip, Authenticator auth) {
		this.id = id;
		this.nounce = nounce;
		this.ip = ip;
		this.auth = auth;
	}

	public String getId() {
		return id;
	}

	public int getNounce() {
		return nounce;
	}

	public String getIp() {
		return ip;
	}

	public Authenticator getAuth() {
		return auth;
	}

	public void setId(String id) {
		this.id = id;
	}

	public void setNounce(int nounce) {
		this.nounce = nounce;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public void setAuth(Authenticator auth) {
		this.auth = auth;
	}

	@Override
	public String toString() {
		return "AuthorizationRequest [id=" + id + ", nounce=" + nounce + ", ip=" + ip + ", auth=" + auth + "]";
	}

}
