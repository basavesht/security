package com.bosch.security.util;

import com.bosch.security.codecs.Encoder;
import com.bosch.security.config.SecurityConfiguration;
import com.bosch.security.crypto.Encryptor;
import com.bosch.security.logger.IntrusionDetector;
import com.bosch.security.random.Randomizer;
import com.bosch.security.validator.Validator;

/**
 * Locator class is provided to getInstance it easy to gain access to the classes in use.
 * Use the set methods to override the reference implementations with instances of any custom implementations.
 */
public final class SecurityHandler 
{

	private static String securityConfigurationImplName = System.getProperty("com.bosch.security.config.SecurityConfiguration","com.bosch.security.config.DefaultSecurityConfiguration");

	//Private Constructor to prevent from instantiation..
	private SecurityHandler() {

	}

	/**
	 * @return the current SecurityConfiguration being used to manage the security configuration for 
	 * ESAPI for this application. 
	 */
	public static SecurityConfiguration securityConfiguration() {
		return ObjFactory.getInstance(securityConfigurationImplName, "SecurityConfiguration");
	}

	/**
	 * @return the current Encoder object being used to encode and decode data for this application. 
	 */
	public static Encoder encoder() {
		return ObjFactory.getInstance(securityConfiguration().getEncoderImplementation(), "Encoder" );
	}

	/**
	 * @return the current Encryptor object being used to encrypt and decrypt data for this application. 
	 */
	public static Encryptor encryptor() {
		return ObjFactory.getInstance(securityConfiguration().getEncryptionImplementation(), "Encryptor" );
	}

	/**
	 * @return the current Randomizer being used to generate random numbers in this application. 
	 */
	public static Randomizer randomizer() {
		return ObjFactory.getInstance(securityConfiguration().getRandomizerImplementation(), "Randomizer" );
	}

	/**
	 * @return the current Validator being used to validate data in this application. 
	 */
	public static Validator validator() {
		return ObjFactory.getInstance(securityConfiguration().getValidationImplementation(), "Validator" );
	}

	/**
	 * @return the current IntrusionDetector being used to monitor for intrusions in this application. 
	 */
	public static IntrusionDetector intrusionDetector() {
		return ObjFactory.getInstance(securityConfiguration().getIntrusionDetectionImplementation(), "IntrusionDetector" );
	}
}
