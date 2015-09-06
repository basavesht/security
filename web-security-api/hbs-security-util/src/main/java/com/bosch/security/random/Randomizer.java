package com.bosch.security.random;

/**
 * The Randomizer interface defines a set of methods for creating
 * cryptographically random numbers and strings. Implementers should be sure to
 * use a strong cryptographic implementation, such as the JCE or BouncyCastle.
 * Weak sources of randomness can undermine a wide variety of security
 * mechanisms. The specific algorithm used is configurable in ESAPI.properties.
 */
public interface Randomizer {

	/**
	 * Gets a random string of a desired length and character set.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param length the length of the string
	 * @param characterSet the set of characters to include in the created random string
	 * @return the random string of the desired length and character set
	 */
	public String getRandomString(int length, char[] characterSet);

	/**
	 * Returns a random boolean.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @return true or false, randomly
	 */
	public boolean getRandomBoolean();

	/**
	 * Gets the random integer. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param min the minimum integer that will be returned
	 * @param max the maximum integer that will be returned
	 * @return the random integer
	 */
	public int getRandomInteger(int min, int max);


	/**
	 * Gets the random long. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @return the random long
	 */
	public long getRandomLong();


	/**
	 * Gets the random real.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * @param min the minimum real number that will be returned
	 * @param max the maximum real number that will be returned
	 * @return the random real
	 */
	public float getRandomReal(float min, float max);


	/**
	 * Generates a specified number of random bytes.
	 * @param n	The requested number of random bytes.
	 * @return The {@code n} random bytes are returned.
	 */
	public byte[] getRandomBytes(int n);
  
}
