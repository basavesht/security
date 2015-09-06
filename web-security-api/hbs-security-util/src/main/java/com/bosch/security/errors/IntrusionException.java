package com.bosch.security.errors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.logger.EventType;

/**
 * An IntrusionException should be thrown anytime an error condition arises that is likely to be the result of an attack
 * in progress. IntrusionExceptions are handled specially by the IntrusionDetector, which is equipped to respond by
 * either specially logging the event, logging out the current user, or invalidating the current user's account.
 * Unlike other exceptions, the IntrusionException is a RuntimeException so that it can be thrown from
 * anywhere and will not require a lot of special exception handling.
 */
public class IntrusionException extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	protected final transient Logger logger = LoggerFactory.getLogger(IntrusionException.class);

	protected String logMessage = null;

	/**
	 * Creates a new instance of IntrusionException.
	 * @param userMessage the message to display to users
	 * @param logMessage the message logged
	 */
	public IntrusionException(String userMessage, String logMessage) {
		super(userMessage);
		this.logMessage = logMessage;
		logger.error(EventType.SECURITY_FAILURE.getEvent() + " {}", "INTRUSION - " + logMessage);
	}

	/**
	 * Instantiates a new intrusion exception.
	 * @param userMessage the message to display to users
	 * @param logMessage the message logged
	 * @param cause the cause
	 */
	public IntrusionException(String userMessage, String logMessage, Throwable cause) {
		super(userMessage, cause);
		this.logMessage = logMessage;
		logger.error(EventType.SECURITY_FAILURE.getEvent() + " {}" + " {}", "INTRUSION - " + logMessage, cause);
	}

	/**
	 * Returns a String containing a message that is safe to display to users
	 * @return a String containing a message that is safe to display to users
	 */
	public String getUserMessage() {
		return getMessage();
	}

	/**
	 * Returns a String that is safe to display in logs, but probably not to users
	 * @return a String containing a message that is safe to display in logs, but probably not to users
	 */
	public String getLogMessage() {
		return logMessage;
	}

}
