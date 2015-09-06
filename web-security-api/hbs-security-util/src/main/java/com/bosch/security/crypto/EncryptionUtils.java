package com.bosch.security.crypto;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.errors.EncryptionException;
import com.bosch.security.util.SecurityHandler;

/**
 * Common Utility class for 
 *  - Encryption
 *  - Decryption
 *  - Hashing
 * @author TEB1PAL
 *
 */
public final class EncryptionUtils 
{
	private static Logger logger = LoggerFactory.getLogger(EncryptionUtils.class);
	private EncryptionUtils () {

	}

	/**
	 * Encrypts the provided plain text using an in-built securely generated random secret key.
	 * @param plaintext
	 * @return
	 * @throws EncryptionException
	 */
	public static String encrypt(final String plaintext) throws EncryptionException
	{
		String encryptedText = null;
		try 
		{
			//Encrypt the plain text using the secret key..
			CipherText ciphertext = SecurityHandler.encryptor().encrypt(new PlainText(plaintext));
			byte[] serializedCt = ciphertext.asPortableSerializedByteArray();
			encryptedText = Base64.encodeBase64URLSafeString(serializedCt);
			return encryptedText;
		} 
		catch (EncryptionException e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw e;
		}
		catch (Exception e) {
			logger.error(" EncryptionException :" + " {}" , e);
			throw new EncryptionException ("Encryption failure during encrypt(String plaintext) - Unknown error", e.getMessage(), e);
		}
	}

	/**
	 * Decrypts the provided plain text using a securely generated random secret key.
	 * @param plaintext
	 * @return
	 * @throws EncryptionException
	 */
	public static String decrypt(final String encryptedText) throws EncryptionException
	{
		String decryptedText = null;
		try 
		{
			//Decode the encrypted string.
			byte[] decodedByteArrayData = Base64.decodeBase64(encryptedText);
			CipherText ctReload = CipherText.fromPortableSerializedBytes(decodedByteArrayData);
			PlainText recoveredPlaintext = SecurityHandler.encryptor().decrypt(ctReload);
			decryptedText = recoveredPlaintext.toString();
			return decryptedText;
		} 
		catch (EncryptionException e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw e;
		}
		catch (Exception e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw new EncryptionException ("Encryption failure during decrypt(String encryptedText) - Unknown error", e.getMessage(), e);
		}
	}

	/**
	 * Encrypts the plain text using the user provided secure key.
	 * @param plaintext
	 * @return
	 * @throws EncryptionException
	 */
	public static String encrypt(final SecretKey secretKey, final String plaintext) throws EncryptionException 
	{
		String encryptedText = null;
		try 
		{
			//Encrypt the plain text using the secret key..
			CipherText ciphertext = SecurityHandler.encryptor().encrypt(secretKey, new PlainText(plaintext));
			byte[] serializedCt = ciphertext.asPortableSerializedByteArray();
			encryptedText = Base64.encodeBase64URLSafeString(serializedCt);
			return encryptedText;
		} 
		catch (EncryptionException e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw e;
		}
		catch (Exception e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw new EncryptionException ("Encryption failure during encrypt(SecretKey secretKey, String plaintext) - Unknown error", e.getMessage(), e);
		}
	}

	/**
	 * Decrypts the provided plain text using a securely generated random secret key.
	 * @param plaintext
	 * @return
	 * @throws EncryptionException
	 */
	public static String decrypt(final SecretKey secretKey, final String encryptedText) throws EncryptionException
	{
		String decryptedText = null;
		try 
		{
			//Decode the encrypted string.
			byte[] decodedByteArrayData = Base64.decodeBase64(encryptedText);
			CipherText ctReload = CipherText.fromPortableSerializedBytes(decodedByteArrayData);
			PlainText recoveredPlaintext = SecurityHandler.encryptor().decrypt(secretKey, ctReload);
			decryptedText = recoveredPlaintext.toString();
			return decryptedText;
		} 
		catch (EncryptionException e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw e;
		}
		catch (Exception e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw new EncryptionException ("Encryption failure during decrypt(SecretKey secretKey, String encryptedText) - Unknown error", e.getMessage(), e);
		}
	}

	/**
	 * Returns a string representation of the hash of the provided plaintext and salt.
	 * @param plaintext
	 * @param salt
	 * @return hashedValue
	 * @throws EncryptionException
	 */
	public static String hash(final String plaintext, final String salt) throws EncryptionException  {
		try {
			return SecurityHandler.encryptor().hash(plaintext, salt);
		} catch (EncryptionException e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw e;
		}
	}

	/**
	 * Returns a string representation of the hash of the provided plaintexT, salt and iterations. 
	 * @param plaintext
	 * @param salt
	 * @param iterations
	 * @return hashedValue
	 * @throws EncryptionException
	 */
	public static String hash(final String plaintext, final String salt, int iterations) throws EncryptionException {
		try {
			return SecurityHandler.encryptor().hash(plaintext, salt, iterations);
		} catch (EncryptionException e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw e;
		}
	}

	/**
	 * Generates a random salt required for hashing functions.
	 * @return
	 */
	public static String getSalt(){
		return Base64.encodeBase64String(SecurityHandler.randomizer().getRandomBytes(SecurityHandler.securityConfiguration().getSaltLength()));
	}

	/**
	 * Generates a random secret key using the configured algorithm and the key length (in properties)
	 * @return
	 * @throws EncryptionException 
	 */
	public static SecretKey getSecretKey() throws EncryptionException {
		String encyrptionAlgo = SecurityHandler.securityConfiguration().getEncryptionAlgorithm();
		Integer encryptionKeyLength = SecurityHandler.securityConfiguration().getEncryptionKeyLength();
		SecretKey secretKey;
		try {
			secretKey = CryptoHelper.generateSecretKey(encyrptionAlgo, encryptionKeyLength);
		} catch (EncryptionException e) {
			logger.error(" EncryptionException :" + " {}", e);
			throw e;
		}
		return secretKey ;
	}
}
