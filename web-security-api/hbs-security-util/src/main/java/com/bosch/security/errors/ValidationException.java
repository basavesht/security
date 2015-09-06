package com.bosch.security.errors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A ValidationException should be thrown to indicate that the data provided by
 * the user or from some other external source does not match the validation
 * rules that have been specified for that data.
 */
public class ValidationException extends EnterpriseSecurityException {

	protected static final long serialVersionUID = 1L;
	private static final Logger logger = LoggerFactory.getLogger(ValidationException.class);

	/** The UI reference that caused this ValidationException */
	private String context;

	/**
	 * Instantiates a new validation exception.
	 */
	protected ValidationException() {

	}

	/**
	 * Creates a new instance of ValidationException.
	 * @param userMessage the message to display to users
	 * @param logMessage the message logged
	 */
	public ValidationException(String userMessage, String logMessage) {
		super(userMessage, logMessage);
	}

	/**
	 * Instantiates a new ValidationException.
	 * 
	 * @param userMessage the message to display to users
	 * @param logMessage  the message logged
	 * @param cause  the cause
	 */
	public ValidationException(String userMessage, String logMessage, Throwable cause) {
		super(userMessage, logMessage, cause);
	}

	/**
	 * Creates a new instance of ValidationException.
	 * @param userMessage the message to display to users
	 * @param logMessage the message logged
	 * @param context the source that caused this exception
	 */
	public ValidationException(String userMessage, String logMessage, String context) {
		super(userMessage, logMessage);
		setContext(context);
	}

	/**
	 * Instantiates a new ValidationException.
	 * @param userMessage the message to display to users
	 * @param logMessage the message logged
	 * @param cause the cause
	 * @param context the source that caused this exception
	 */
	public ValidationException(String userMessage, String logMessage, Throwable cause, String context) {
		super(userMessage, logMessage, cause);
		setContext(context);
		logger.error(userMessage + " {}" + " {}", logMessage, cause);
	}

	/**
	 * Returns the UI reference that caused this ValidationException
	 * @return context, the source that caused the exception, stored as a string
	 */
	public String getContext() {
		return context;
	}

	/**
	 * Set's the UI reference that caused this ValidationException
	 * @param context the context to set, passed as a String
	 */
	public void setContext(String context) {
		this.context = context;
	}
}
