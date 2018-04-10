package stgc_tlp.exceptions;

import java.io.IOException;

public class UnauthorizedException extends IOException {


	private static final long serialVersionUID = 3424367383844182438L;

	public UnauthorizedException() {}
	  
	  public UnauthorizedException(String paramString)
	  {
	    super(paramString);
	  }
	  
	  public UnauthorizedException(String paramString, Throwable paramThrowable)
	  {
	    super(paramString, paramThrowable);
	  }
	  
	  public UnauthorizedException(Throwable paramThrowable)
	  {
	    super(paramThrowable);
	  }
	
}
