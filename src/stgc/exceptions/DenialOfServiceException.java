package stgc.exceptions;

import java.io.IOException;

public class DenialOfServiceException extends IOException {

	private static final long serialVersionUID = -3521015731553623214L;

	public DenialOfServiceException() {}

	public DenialOfServiceException(String paramString)
	{
		super(paramString);
	}

	public DenialOfServiceException(String paramString, Throwable paramThrowable)
	{
		super(paramString, paramThrowable);
	}

	public DenialOfServiceException(Throwable paramThrowable)
	{
		super(paramThrowable);
	}
}
