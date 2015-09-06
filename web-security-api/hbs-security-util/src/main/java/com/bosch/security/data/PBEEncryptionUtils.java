package com.bosch.security.data;

import java.security.NoSuchProviderException;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.PropertyValueEncryptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.crypto.SecurityProviderLoader;
import com.bosch.security.errors.EncryptionException;
import com.bosch.security.logger.EventType;
import com.bosch.security.util.SecurityHandler;

/**
 * This class uses the JASYPT API for decrypting the sensitive data stored in property files. 
 * Ensure that the encrypted data passed for the decryption is done using JASYPT api...
 * PasswordBased Encryption algorithm as configured in the property file 
 * is used for encryption/decryption.
 * @author TEB1PAL
 */
public final class PBEEncryptionUtils 
{
	private static Logger logger = LoggerFactory.getLogger(PBEEncryptionUtils.class);
	private static final String ENCRYPTED_VALUE_PREFIX = "ENC(";
	private static final String ENCRYPTED_VALUE_SUFFIX = ")";

	//Do not allow to create instances...
	private PBEEncryptionUtils(){

	}

	//Load the preferred JCE provider if one has been specified else leave as is.
	static {
		try {
			SecurityProviderLoader.loadPreferredPBEEncryptionJCEProvider();
		} catch (NoSuchProviderException ex) {
			logger.error(EventType.SECURITY_FAILURE.getEvent() + "{}" + "{}", "JavaEncryptor failed to load preferred JCE provider.", ex);
			throw new ExceptionInInitializerError(ex);
		}
	}

	/**
	 * Encrypt data (PBEEncrytion using JASYPT)
	 * @param message
	 * @param encryptionPassword
	 * @return
	 * @throws EncryptionException 
	 */
	public static String encrypt (final String message, final String encryptionPassword) throws EncryptionException
	{
		try  {
			final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
			encryptor.setPassword(encryptionPassword); // Encryption Key Password
			encryptor.setAlgorithm(SecurityHandler.securityConfiguration().getPBEEncryptionAlgorithm());
			return encryptor.encrypt(message); // Data to be encrypted.
		} 
		catch (Exception e) {
			logger.error(" EncryptionException :" + " {}" , e);
			throw new EncryptionException ("Encryption failure during PBE encrypt - Unknown error", e.getMessage(), e);
		}
	}

	/**
	 * Decrypt data (PBEEncrytion using JASYPT)
	 * @param encryptedPassword
	 * @param encryptionPassword
	 * @return
	 * @throws EncryptionException 
	 */
	public static String decrypt (final String encryptedPassword, final String encryptionPassword) throws EncryptionException 
	{
		try {
			final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
			encryptor.setPassword(encryptionPassword); // Encryption Key Password
			encryptor.setAlgorithm(SecurityHandler.securityConfiguration().getPBEEncryptionAlgorithm());
			return encryptor.decrypt(decode(encryptedPassword)); // Data to be encrypted.
		} 
		catch (Exception e) {
			logger.error(" EncryptionException :" + " {}" , e);
			throw new EncryptionException ("Encryption failure during PBE encrypt - Unknown error", e.getMessage(), e);
		}
	}

	/**
	 * Internal method for decoding a value if needed.
	 * @param encodedValue
	 * @return
	 */
	private static String decode(final String encodedValue) {
		if (!PropertyValueEncryptionUtils.isEncryptedValue(encodedValue)) {
			return encodedValue;
		}
		return getInnerEncryptedValue(encodedValue);

	}

	/**
	 * Gets only the encrypted value...
	 * @param value
	 * @return
	 */
	private static String getInnerEncryptedValue(final String value) {
		return value.substring(
				ENCRYPTED_VALUE_PREFIX.length(),
				(value.length() - ENCRYPTED_VALUE_SUFFIX.length()));
	}
}
