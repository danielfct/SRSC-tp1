package stgc.exceptions;

import java.io.IOException;

public class DataReplyingException extends IOException {

	private static final long serialVersionUID = 919225818588820157L;

	public DataReplyingException() {}
	  
	  public DataReplyingException(String paramString)
	  {
	    super(paramString);
	  }
	  
	  public DataReplyingException(String paramString, Throwable paramThrowable)
	  {
	    super(paramString, paramThrowable);
	  }
	  
	  public DataReplyingException(Throwable paramThrowable)
	  {
	    super(paramThrowable);
	  }

}
