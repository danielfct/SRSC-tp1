package stgc.exceptions;

import java.io.IOException;

public class UserUnregisteredException extends IOException {

	private static final long serialVersionUID = 4506927623296586800L;

	public UserUnregisteredException() {}
	  
	  public UserUnregisteredException(String paramString)
	  {
	    super(paramString);
	  }
	  
	  public UserUnregisteredException(String paramString, Throwable paramThrowable)
	  {
	    super(paramString, paramThrowable);
	  }
	  
	  public UserUnregisteredException(Throwable paramThrowable)
	  {
	    super(paramThrowable);
	  }
	
}
