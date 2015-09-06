package com.bosch.security.errors;

/**
 * An EncryptionRuntimeException should be thrown for any problems related to
 * encryption, hashing, or digital signatures.
 */
public class EncryptionRuntimeException extends EnterpriseSecurityRuntimeException 
{
	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new EncryptionException.
	 */
	protected EncryptionRuntimeException() {

	}

    /**
     * Creates a new instance of EncryptionException.
     * 
     * @param userMessage
     *            the message displayed to the user
     * @param logMessage
	 * 			  the message logged
     */
    public EncryptionRuntimeException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new EncryptionException.
     * 
     * @param userMessage
     *            the message displayed to the user
     * @param logMessage
	 * 			  the message logged
     * @param cause
     *            the cause
     */
    public EncryptionRuntimeException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }
}
