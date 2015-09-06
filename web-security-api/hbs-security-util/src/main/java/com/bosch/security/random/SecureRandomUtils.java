package com.bosch.security.random;

import java.util.UUID;

import com.bosch.security.codecs.EncoderConstants;
import com.bosch.security.util.SecurityHandler;

public class SecureRandomUtils 
{	
	/**
	 * Gets a random string of a desired length and character set.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param length the length of the string
	 * @param characterSet the set of characters to include in the created random string
	 * @return the random string of the desired length and character set
	 */
	public static String getRandomString(int length, char[] characterSet) {
		return SecurityHandler.randomizer().getRandomString(length, characterSet);
	}
	
	/**
	 * Gets the random integer. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param min the minimum integer that will be returned
	 * @param max the maximum integer that will be returned
	 * @return the random integer
	 */
	public static int getRandomInteger() {
		return SecurityHandler.randomizer().getRandomInteger(Integer.MIN_VALUE, Integer.MAX_VALUE);
	}
	
	/**
	 * Gets the random integer between the provided limits. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param min the minimum integer that will be returned
	 * @param max the maximum integer that will be returned
	 * @return the random integer
	 */
	public static int getRandomInteger(int min, int max) {
		return SecurityHandler.randomizer().getRandomInteger(min, max);
	}

	/**
	 * Gets the random long. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @return the random long
	 */
	public static long getRandomLong() {
		return SecurityHandler.randomizer().getRandomLong();    
	}

	/**
	 * Gets the random real.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param min the minimum real number that will be returned
	 * @param max the maximum real number that will be returned
	 * @return the random real
	 */
	public static float getRandomReal(float min, float max) {
		return SecurityHandler.randomizer().getRandomReal(min, max);
	}

	/**
	 * Generates a random GUID.  This method could use a hash of random Strings, the current time,
	 * and any other random data available.  The format is a well-defined sequence of 32 hex digits 
	 * grouped into chunks of 8-4-4-4-12.
	 * @return the GUID
	 */
	public static String getRandomGUID() {
		return UUID.randomUUID().toString();
	}

	/**
	 * Generates a specified number of random bytes.
	 * @param n	The requested number of random bytes.
	 * @return The {@code n} random bytes are returned.
	 */
	public static byte[] getRandomBytes(int n) {
		return SecurityHandler.randomizer().getRandomBytes(n);
	}

	/**
	 * Gets a random alphnumeric of a desired length. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param length the length of the string
	 * @return the random string of the desired length and character set
	 */
	public static String getRandomAlphanumeric(int length) {
		return SecurityHandler.randomizer().getRandomString(length, EncoderConstants.CHAR_ALPHANUMERICS);
	}

	/**
	 * Gets a random Session Id of a defined length. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param length the length of the string
	 * @return the random string of the desired length and character set
	 */
	public static String getRandomSessionId() {
		String sessionId = getRandomGUID();
		return sessionId;
	}

	/**
	 * Returns a random boolean. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @return true or false, randomly
	 */
	public static boolean getRandomBoolean() {
		return SecurityHandler.randomizer().getRandomBoolean();
	}

	/**
	 * Returns an unguessable random filename with the specified extension.  This method could call
	 * getRandomString(length, charset) from this Class with the desired length and alphanumerics as the charset 
	 * then merely append "." + extension.
	 * @param extension extension to add to the random filename
	 * @return a random unguessable filename ending with the specified extension
	 */
	public static String getRandomFilename(String extension) {
		String fn = getRandomString(12, EncoderConstants.CHAR_ALPHANUMERICS) + "." + extension;
		return fn;
	}

}
