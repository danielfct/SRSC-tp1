package stgc;

import java.io.Serializable;
import java.security.Key;


class TicketAS implements Serializable {

	private static final long serialVersionUID = 6146667052618121076L;
	
	private String client;
	private String ip;
	private String ciphersuite;
	private Key sessionKey;
	private String macAlgorithm;
	private Key macKey;
	private long timeout;
	
	public TicketAS(String client, String ip, String ciphersuite, Key sessionKey, String macAlgorithm, Key macKey) {
		this.client = client;
		this.ip = ip;
		this.ciphersuite = ciphersuite;
		this.sessionKey = sessionKey;
		this.macAlgorithm = macAlgorithm;
		this.macKey = macKey;
		this.timeout = System.currentTimeMillis() + 60000L; // up to 1 hour of authorization
	}

	public String getClient() {
		return client;
	}

	public void setClient(String client) {
		this.client = client;
	}

	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public String getCiphersuite() {
		return ciphersuite;
	}

	public void setCiphersuite(String ciphersuite) {
		this.ciphersuite = ciphersuite;
	}

	public Key getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(Key sessionKey) {
		this.sessionKey = sessionKey;
	}

	public String getMac() {
		return macAlgorithm;
	}

	public void setMacAlgorithm(String macAlgorithm) {
		this.macAlgorithm = macAlgorithm;
	}

	public Key getMacKey() {
		return macKey;
	}

	public void setMacKey(Key macKey) {
		this.macKey = macKey;
	}
	
	@Override
	public String toString() {
		return "TicketAS [client=" + client + ", ip=" + ip + ", ciphersuite=" + ciphersuite + ", sessionKey="
				+ sessionKey + ", macAlgorithm=" + macAlgorithm + ", macKey=" + macKey + "]";
	}

	public boolean isExpired() {
		return System.currentTimeMillis() >= timeout;
	}

}