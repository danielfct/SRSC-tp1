package stgc.exceptions;

public class InvalidAddressException extends Exception {

	private static final long serialVersionUID = -5676554278295576626L;

	public InvalidAddressException() {}
	  
	  public InvalidAddressException(String paramString)
	  {
	    super(paramString);
	  }
	  
	  public InvalidAddressException(String paramString, Throwable paramThrowable)
	  {
	    super(paramString, paramThrowable);
	  }
	  
	  public InvalidAddressException(Throwable paramThrowable)
	  {
	    super(paramThrowable);
	  }
	  
}
