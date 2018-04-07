package stgc_tlp.exceptions;

import java.io.IOException;

public class DataIntegrityAuthenticityException extends IOException {

	private static final long serialVersionUID = -5625287891011875882L;

	public DataIntegrityAuthenticityException() {}
	  
	  public DataIntegrityAuthenticityException(String paramString)
	  {
	    super(paramString);
	  }
	  
	  public DataIntegrityAuthenticityException(String paramString, Throwable paramThrowable)
	  {
	    super(paramString, paramThrowable);
	  }
	  
	  public DataIntegrityAuthenticityException(Throwable paramThrowable)
	  {
	    super(paramThrowable);
	  }
}
