package com.bosch.security.config;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The {@code SecurityConfiguration} interface stores all configuration information. 
 * <br><br>
 * Protection of this configuration information is critical to the secure
 * operation of the application. You should use operating system
 * access controls to limit access to wherever the configuration information is
 * stored.
 * <br><br>
 * Please note that adding another layer of encryption does not make the
 * attackers job much more difficult.
 * It's up to the reference implementation to decide whether this file should
 * be encrypted or not.
 * <br><br>
 */
public interface SecurityConfiguration 
{
	/**
	 * Returns the fully qualified classname of the Encoder implementation.
	 */
	public String getEncoderImplementation();

	/**
	 * Returns the fully qualified classname of the Intrusion Detection implementation.
	 */
	public String getIntrusionDetectionImplementation();

	/**
	 * Returns the fully qualified classname of the Randomizer implementation.
	 */
	public String getRandomizerImplementation();

	/**
	 * Returns the fully qualified classname of the Encryption implementation.
	 */
	public String getEncryptionImplementation();

	/**
	 * Returns the fully qualified classname of the Validation implementation.
	 */
	public String getValidationImplementation();

	/**
	 * Returns the validation pattern for a particular type
	 * @param typeName
	 * @return the validation pattern
	 */
	public Pattern getValidationPattern( String typeName );

	/**
	 * Returns a list of XSS blacklisted patterns.
	 * @return a list of XSS blacklisted patterns.
	 */
	public List<Pattern> getXSSPatterns() ;

	/**
	 * Determines whether ESAPI will accept "lenient" dates when attempt
	 * to parse dates. Controlled by ESAPI property
	 * {@code Validator.AcceptLenientDates}, which defaults to {@code false}
	 * if unset.
	 * 
	 * @return True if lenient dates are accepted; false otherwise.
	 * @see java.text.DateFormat#setLenient(boolean)
	 */
	public boolean getLenientDatesAccepted();

	/**
	 * Gets the key length to use in cryptographic operations declared in the properties file.
	 * @return the key length.
	 */
	public int getEncryptionKeyLength();

	/**
	 * Salt length required to hash the password.
	 * @return
	 */
	public int getSaltLength();

	/**
	 * Gets the encryption algorithm used to protect data. 
	 * @return the current encryption algorithm
	 */
	public String getEncryptionAlgorithm();

	/**
	 * Gets the PBE based encryption algorithm used to protect data. 
	 * @return the current encryption algorithm
	 */
	public String getPBEEncryptionAlgorithm();

	/**
	 * PBE based encryption JCE provider. 
	 * @return the current encryption algorithm
	 */
	public String getPBEEncryptionJCEProvider();

	/**
	 * Retrieve the <i>cipher transformation</i>. In general, the cipher transformation
	 * is a specification of cipher algorithm, cipher mode, and padding scheme
	 * and in general, is a {@code String} that takes the following form:
	 * <pre>
	 * 		<i>cipher_alg</i>/<i>cipher_mode[bits]</i>/<i>padding_scheme</i>
	 * </pre>
	 * where <i>cipher_alg</i> is the JCE cipher algorithm (e.g., "DESede"),
	 * <i>cipher_mode</i> is the cipher mode (e.g., "CBC", "CFB", "CTR", etc.),
	 * and <i>padding_scheme</i> is the cipher padding scheme (e.g., "NONE" for
	 * no padding, "PKCS5Padding" for PKCS#5 padding, etc.) and where
	 * <i>[bits]</i> is an optional bit size that applies to certain cipher
	 * modes such as {@code CFB} and {@code OFB}. Using modes such as CFB and
	 * OFB, block ciphers can encrypt data in units smaller than the cipher's
	 * actual block size. When requesting such a mode, you may optionally
	 * specify the number of bits to be processed at a time. This generally must
	 * be an integral multiple of 8-bits so that it can specify a whole number
	 * of octets. 
	 * </p><p>
	 * Examples are:
	 * <pre>
	 * 		"AES/ECB/NoPadding"		// Default for ESAPI Java 1.4 (insecure)
	 * 		"AES/CBC/PKCS5Padding"	// Default for ESAPI Java 2.0
	 * 		"DESede/OFB32/PKCS5Padding"
	 * </pre>
	 * <b>NOTE:</b> Occasionally, in cryptographic literature, you may also
	 * see the key size (in bits) specified after the cipher algorithm in the
	 * cipher transformation. Generally, this is done to account for cipher
	 * algorithms that have variable key sizes. The Blowfish cipher for example
	 * supports key sizes from 32 to 448 bits. So for Blowfish, you might see
	 * a cipher transformation something like this:
	 * <pre>
	 * 		"Blowfish-192/CFB8/PKCS5Padding"
	 * </pre>
	 * in the cryptographic literature. It should be noted that the Java
	 * Cryptography Extensions (JCE) do not generally support this (at least
	 * not the reference JCE implementation of "SunJCE"), and therefore it
	 * should be avoided.
	 * @return	The cipher transformation.
	 */
	public String getCipherTransformation();

	/**
	 * Retrieve the <i>preferred</i> JCE provider for your application.
	 * ESAPI 2.0 now allows setting the property
	 * {@code Encryptor.PreferredJCEProvider} in the
	 * {@code ESAPI.properties} file, which will cause the specified JCE
	 * provider to be automatically and dynamically loaded (assuming that
	 * {@code SecurityManager} permissions allow) as the Ii>preferred</i>
	 * JCE provider. (Note this only happens if the JCE provider is not already
	 * loaded.) This method returns the property {@code Encryptor.PreferredJCEProvider}.
	 * </p<p>
	 * By default, this {@code Encryptor.PreferredJCEProvider} property is set
	 * to an empty string, which means that the preferred JCE provider is not
	 * changed.
	 * @return The property {@code Encryptor.PreferredJCEProvider} is returned.
	 * @see org.owasp.esapi.crypto.SecurityProviderLoader
	 */
	public String getPreferredJCEProvider();

	/**
	 * Determines whether the {@code CipherText} should be used with a Message
	 * Authentication Code (MAC). Generally this makes for a more robust cryptographic
	 * scheme, but there are some minor performance implications. Controlled by
	 * the ESAPI property <i>Encryptor.CipherText.useMAC</i>.
	 * </p><p>
	 * For further details, see the "Advanced Usage" section of
	 * <a href="http://www.owasp.org/ESAPI_2.0_ReleaseNotes_CryptoChanges.html">
	 * "Why Is OWASP Changing ESAPI Encryption?"</a>.
	 * </p>
	 * @return	{@code true} if a you want a MAC to be used, otherwise {@code false}.
	 */
	public boolean useMACforCipherText();

	/**
	 * Indicates whether the {@code PlainText} objects may be overwritten after
	 * they have been encrypted. Generally this is a good idea, especially if
	 * your VM is shared by multiple applications (e.g., multiple applications
	 * running in the same J2EE container) or if there is a possibility that
	 * your VM may leave a core dump (say because it is running non-native
	 * Java code.
	 * <p>
	 * Controlled by the property {@code Encryptor.PlainText.overwrite} in
	 * the {@code ESAPI.properties} file.
	 * </p>
	 * @return	True if it is OK to overwrite the {@code PlainText} objects
	 *			after encrypting, false otherwise.
	 */
	public boolean overwritePlainText();

	/**
	 * Get a string indicating how to compute an Initialization Vector (IV).
	 * Currently supported modes are "random" to generate a random IV or
	 * "fixed" to use a fixed (static) IV. If a "fixed" IV is chosen, then the
	 * the value of this fixed IV must be specified as the property
	 * {@code Encryptor.fixedIV} and be of the appropriate length.
	 * @return A string specifying the IV type. Should be "random" or "fixed".
	 * @see #getFixedIV()
	 */
	public String getIVType();

	/**
	 * If a "fixed" (i.e., static) Initialization Vector (IV) is to be used,
	 * this will return the IV value as a hex-encoded string.
	 * @return The fixed IV as a hex-encoded string.
	 */
	public String getFixedIV();

	/**
	 * Return a {@code List} of strings of combined cipher modes that support
	 * <b>both</b> confidentiality and authenticity. These would be preferred
	 * cipher modes to use if your JCE provider supports them. If such a
	 * cipher mode is used, no explicit <i>separate</i> MAC is calculated as part of
	 * the {@code CipherText} object upon encryption nor is any attempt made
	 * to verify the same on decryption.
	 * </p><p>
	 * The list is taken from the comma-separated list of cipher modes specified
	 * by the ESAPI property
	 * {@code Encryptor.cipher_modes.combined_modes}.
	 * 
	 * @return The parsed list of comma-separated cipher modes if the property
	 * was specified in {@code ESAPI.properties}; otherwise the empty list is
	 * returned.
	 */
	public List<String> getCombinedCipherModes();

	/**
	 * Return {@code List} of strings of additional cipher modes that are
	 * permitted (i.e., in <i>addition<i> to those returned by
	 * {@link #getPreferredCipherModes()}) to be used for encryption and
	 * decryption operations.
	 * </p><p>
	 * The list is taken from the comma-separated list of cipher modes specified
	 * by the ESAPI property
	 * {@code Encryptor.cipher_modes.additional_allowed}.
	 * 
	 * @return The parsed list of comma-separated cipher modes if the property
	 * was specified in {@code ESAPI.properties}; otherwise the empty list is
	 * returned.
	 *
	 * @see #getPreferredCipherModes() 
	 */
	public List<String> getAdditionalAllowedCipherModes();

	/**
	 * Gets the hashing algorithm to hash data.
	 * @return the current hashing algorithm
	 */
	public String getHashAlgorithm();

	/**
	 * Gets the hash iterations to hash data.
	 * @return the current hashing algorithm
	 */
	public int getHashIterations();

	/**
	 * Gets the character encoding scheme supported by this application. This is used to set the
	 * character encoding scheme on requests and responses when setCharacterEncoding() is called
	 * on SafeRequests and SafeResponses. This scheme is also used for encoding/decoding URLs 
	 * and any other place where the current encoding scheme needs to be known.
	 * <br><br>
	 * Note: This does not get the configured response content type. That is accessed by calling 
	 * getResponseContentType().
	 * 
	 * @return the current character encoding scheme
	 */
	public String getCharacterEncoding();

	/**
	 * Return true if multiple encoding is allowed
	 * @return whether multiple encoding is allowed when canonicalizing data
	 */
	public boolean getAllowMultipleEncoding();

	/**
	 * Return true if mixed encoding is allowed
	 * @return whether mixed encoding is allowed when canonicalizing data
	 */
	public boolean getAllowMixedEncoding();

	/**
	 * Returns the List of Codecs to use when canonicalizing data
	 * @return the codec list
	 */
	public List<String> getDefaultCanonicalizationCodecs();

	/**
	 * Gets the random number generation algorithm used to generate random numbers where needed.
	 * @return the current random number generation algorithm
	 */
	public String getRandomAlgorithm();

	/**
	 * Allows for complete disabling of all intrusion detection mechanisms
	 * @return true if intrusion detection should be disabled
	 */
	public boolean getDisableIntrusionDetection();

	/**
	 * Gets the intrusion detection quota for the specified event.
	 * @param eventName the name of the event whose quota is desired
	 * @return the Quota that has been configured for the specified type of event
	 */
	public Threshold getQuota(String eventName);

	/**
	 * Gets a file from the resource directory
	 * @param filename The file name resource.
	 * @return A {@code File} object representing the specified file name or null if not found.
	 */
	public File getResourceFile(String filename);

	/**
	 * Gets an InputStream to a file in the resource directory
	 * @param filename A file name in the resource directory.
	 * @return An {@code InputStream} to the specified file name in the resource directory.
	 * @throws IOException If the specified file name cannot be found or opened for reading.
	 */
	public InputStream getResourceStream( String filename ) throws IOException;

	/**
	 * Models a simple threshold as a count and an interval, along with a set of actions to take if 
	 * the threshold is exceeded. These thresholds are used to define when the accumulation of a particular event
	 * has met a set number within the specified time period. Once a threshold value has been met, various
	 * actions can be taken at that point.
	 */
	public static class Threshold
	{
		/** The name of this threshold. */
		public String name = null;

		/** The count at which this threshold is triggered. */
		public int count = 0;

		/** 
		 * The time frame within which 'count' number of actions has to be detected in order to
		 * trigger this threshold.
		 */
		public long interval = 0;

		/**
		 * The list of actions to take if the threshold is met. It is expected that this is a list of Strings, but 
		 * your implementation could have this be a list of any type of 'actions' you wish to define. 
		 */
		public List<String> actions = null;

		/**
		 * Constructs a threshold that is composed of its name, its threshold count, the time window for
		 * the threshold, and the actions to take if the threshold is triggered.
		 * 
		 * @param name The name of this threshold.
		 * @param count The count at which this threshold is triggered.
		 * @param interval The time frame within which 'count' number of actions has to be detected in order to
		 * trigger this threshold.
		 * @param actions The list of actions to take if the threshold is met.
		 */
		public Threshold(String name, int count, long interval, List<String> actions) {
			this.name = name;
			this.count = count;
			this.interval = interval;
			this.actions = actions;
		}
	}

	/**
	 * Get the maximum [byte[]) size limit allowed for the cipher text.
	 * Few instance of denial of service attacks were found when the cipher text length which got computed went extremely high.
	 * @return
	 */
	public int getMaxAllowedCipherTextSize();
	
	/**
	 * Ensure no CRLF injection into logs for forging records
	 * @return
	 */
	public boolean getLogEncodingRequired();
}
