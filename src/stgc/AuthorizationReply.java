package stgc;

import java.io.Serializable;

final class AuthorizationReply implements Serializable {

	private static final long serialVersionUID = 780454424615914681L;
	
	private String digestedPassword;
	private int nouncePlusOne;
	private int nounceS;
	private TicketAS ticket;
	
	public AuthorizationReply(String digestedPassword, int nouncePlusOne, int nounceS, TicketAS ticket) {
		this.digestedPassword = digestedPassword;
		this.nouncePlusOne = nouncePlusOne;
		this.nounceS = nounceS;
		this.ticket = ticket;
	}
	
	public String getDigestedPassword() {
		return digestedPassword;
	}
	
	public void setDigestedPassword(String digestedPassword) {
		this.digestedPassword = digestedPassword;
	}

	public int getNouncePlusOne() {
		return nouncePlusOne;
	}

	public void setNouncePlusOne(int nouncePlusOne) {
		this.nouncePlusOne = nouncePlusOne;
	}

	public int getNounceS() {
		return nounceS;
	}

	public void setNounceS(int nounceS) {
		this.nounceS = nounceS;
	}

	public TicketAS getTicket() {
		return ticket;
	}

	public void setTicket(TicketAS ticket) {
		this.ticket = ticket;
	}

	@Override
	public String toString() {
		return "AuthorizationReply [nouncePlusOne=" + nouncePlusOne + ", nounceS=" + nounceS + ", ticket=" + ticket + "]";
	}

	
	
}
