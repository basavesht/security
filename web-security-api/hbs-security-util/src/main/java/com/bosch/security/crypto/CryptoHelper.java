package com.bosch.security.crypto;

import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.bosch.security.errors.EncryptionException;
import com.bosch.security.util.SecurityHandler;

/**
 * Utility class to provide some convenience methods for encryption, decryption, etc.
 */
public class CryptoHelper 
{
	//Utility class
	private CryptoHelper() {
		;	
	}

	/**
	 * Generate a random secret key appropriate to the specified cipher algorithm
	 * and key size.
	 * @param alg	The cipher algorithm or cipher transformation.
	 * @param keySize	The key size, in bits.
	 * @return	A random {@code SecretKey} is returned.
	 * @throws EncryptionException.
	 */
	public static SecretKey generateSecretKey(String alg, int keySize) throws EncryptionException
	{
		assert alg != null : "Algorithm must not be null.";		
		assert !alg.equals("") : "Algorithm must not be empty";	
		assert keySize > 0 : "Key size must be positive.";	

		String[] cipherSpec = alg.split("/");
		String cipherAlg = cipherSpec[0];
		try {
			if (cipherAlg.toUpperCase().startsWith("PBEWITH") ) {
				cipherAlg = "PBE";
			}
			KeyGenerator kgen = KeyGenerator.getInstance(cipherAlg);
			kgen.init(keySize);
			return kgen.generateKey();
		} 
		catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Failed to generate random secret key",
					"Invalid algorithm. Failed to generate secret key for " + alg + " with size of " + keySize + " bits.", e);
		} 
		catch (InvalidParameterException e) {
			throw new EncryptionException("Failed to generate random secret key - invalid key size specified.",
					"Invalid key size. Failed to generate secret key for " + alg + " with size of " + keySize + " bits.", e);
		}
	}

	/**
	 * Return true if specified cipher mode is one of those specified in the
	 * {@code security-config.properties} file that supports both confidentiality
	 * <b>and</b> authenticity (i.e., a "combined cipher mode" as NIST refers
	 * to it).
	 * @param cipherMode
	 * @return true if the specified cipher mode is in the comma-separated list of cypher modes
	 */
	public static boolean isCombinedCipherMode(String cipherMode){
		assert cipherMode != null : "Cipher mode may not be null";
		assert ! cipherMode.equals("") : "Cipher mode may not be empty string";
		List<String> combinedCipherModes = SecurityHandler.securityConfiguration().getCombinedCipherModes();
		return combinedCipherModes.contains( cipherMode );
	}

	/**
	 * Return true if specified cipher mode is one that may be used for
	 * encryption / decryption
	 * @param cipherMode 
	 * @return true if the specified cipher mode is in the comma-separated list of cypher modes
	 */
	public static boolean isAllowedCipherMode(String cipherMode)
	{
		if (isCombinedCipherMode(cipherMode) ) {
			return true;
		}
		List<String> extraCipherModes = SecurityHandler.securityConfiguration().getAdditionalAllowedCipherModes();
		return extraCipherModes.contains( cipherMode );
	}

	/**
	 * Overwrite a byte array with a specified byte. This is frequently done
	 * to a plaintext byte array so the sensitive data is not lying around
	 * exposed in memory.
	 * @param bytes	The byte array to be overwritten.
	 * @param x The byte array {@code bytes} is overwritten with this byte.
	 */
	public static void overwrite(byte[] bytes, byte x){
		Arrays.fill(bytes, x);
	}

	/**
	 * Overwrite a byte array with the byte containing '*'.
	 * @param bytes The byte array to be overwritten.
	 */
	public static void overwrite(byte[] bytes){
		overwrite(bytes, (byte)'*');
	}

	/**
	 * Same as {@code System.arraycopy(src, 0, dest, 0, length)}.
	 * 
	 * @param      src      the source array.
	 * @param      dest     the destination array.
	 * @param      length   the number of array elements to be copied.
	 * @exception  IndexOutOfBoundsException
	 * @exception  NullPointerException
	 */
	public static void copyByteArray(final byte[] src, byte[] dest, int length){
		System.arraycopy(src, 0, dest, 0, length);
	}

	/**
	 * Same as {@code copyByteArray(src, dest, src.length)}.
	 * @param      src      the source array.
	 * @param      dest     the destination array.
	 * @exception  IndexOutOfBoundsException
	 * @exception  NullPointerException 
	 */
	public static void copyByteArray(final byte[] src, byte[] dest){
		copyByteArray(src, dest, src.length);
	}

	/**
	 * A "safe" array comparison that is not vulnerable to side-channel
	 * "timing attacks". All comparisons of non-null, equal length bytes should
	 * take same amount of time. We use this for cryptographic comparisons.
	 * @param b1   A byte array to compare.
	 * @param b2   A second byte array to compare.
	 * @return   
	 */
	public static boolean arrayCompare(byte[] b1, byte[] b2) {
		if ( b1 == b2 ) {
			return true;
		}
		if ( b1 == null || b2 == null ) {
			return (b1 == b2);
		}
		if ( b1.length != b2.length ) {
			return false;
		}

		// XOR the 2 current bytes and then OR with the outstanding result.
		int result = 0;
		for(int i = 0; i < b1.length; i++) {
			result |= (b1[i] ^ b2[i]);
		}
		return (result == 0) ? true : false;
	}
	
   /**
    * Check the cipherText length before instantiating byte[]
    * @param ciphertextLen
    * @return
    */
	public static boolean exceedsMaxSizeLimit(int ciphertextLen) {
		int maxCipherTextSize = SecurityHandler.securityConfiguration().getMaxAllowedCipherTextSize();
		if(ciphertextLen > 0  && ciphertextLen > maxCipherTextSize) {
			return true;
		}
		return false;
	}
}
