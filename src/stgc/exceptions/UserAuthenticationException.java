package stgc.exceptions;

import java.io.IOException;

public class UserAuthenticationException extends IOException {

	private static final long serialVersionUID = -2723588432905279164L;

	public UserAuthenticationException() {}
	  
	  public UserAuthenticationException(String paramString)
	  {
	    super(paramString);
	  }
	  
	  public UserAuthenticationException(String paramString, Throwable paramThrowable)
	  {
	    super(paramString, paramThrowable);
	  }
	  
	  public UserAuthenticationException(Throwable paramThrowable)
	  {
	    super(paramThrowable);
	  }
	
}
