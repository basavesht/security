package com.bosch.security.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.codec.binary.Base64;

import com.bosch.security.errors.ConfigurationException;

/**
 * The reference {@code SecurityConfiguration} manages all the settings used by the Security in a single place. In this reference
 * implementation, resources can be put in several locations, which are searched in the following order:
 * 1) Inside a directory set with a call to SecurityConfiguration.setResourceDirectory( "C:\temp\resources" ).
 * 2) Inside the System.getProperty( "com.bosch.security.resources" ) directory.
 * 		java -Dcom.bosch.security.resources="C:\temp\resources"
 *    You may have to add this to the start-up script that starts your web server. 
 * 4) The directory on the classpath. (The former for backward compatibility.)
 * Once the Configuration is initialized with a resource directory, you can edit it to set things like master
 * keys and passwords, logging locations, error thresholds, and allowed file extensions.
 */
public class DefaultSecurityConfiguration implements SecurityConfiguration 
{
	private static volatile SecurityConfiguration instance = null;

	public static SecurityConfiguration getInstance() {
		if ( instance == null ) {
			synchronized (DefaultSecurityConfiguration.class) {
				if ( instance == null ) {
					instance = new DefaultSecurityConfiguration();
				}
			}
		}
		return instance;
	}

	private Properties properties = null;
	private String cipherXformFromSecurityProp = null;
	private String cipherXformCurrent = null;

	/** The name of the Security property file */
	public static final String RESOURCE_FILE = "security-config.properties";

	public static final String ALLOW_MULTIPLE_ENCODING = "Encoder.AllowMultipleEncoding";
	public static final String ALLOW_MIXED_ENCODING	= "Encoder.AllowMixedEncoding";
	public static final String CANONICALIZATION_CODECS = "Encoder.DefaultCodecList";
	public static final String LOG_ENCODING_REQUIRED = "Encoder.LogEncodingRequired";

	public static final String DISABLE_INTRUSION_DETECTION  = "IntrusionDetector.Disable";

	public static final String KEY_LENGTH = "Encryptor.EncryptionKeyLength";
	public static final String ENCRYPTION_ALGORITHM = "Encryptor.EncryptionAlgorithm";
	public static final String PBE_ENCRYPTION_ALGORITHM = "Encryptor.PBEEncryptionAlgorithm";
	public static final String HASH_ALGORITHM = "Encryptor.HashAlgorithm";
	public static final String HASH_ITERATIONS = "Encryptor.HashIterations";
	public static final String CHARACTER_ENCODING = "Encryptor.CharacterEncoding";
	public static final String RANDOM_ALGORITHM = "Encryptor.RandomAlgorithm";
	public static final String SALT_LENGTH = "Encryptor.SaltLength";
	public static final String MAX_ALLOWED_CIPHER_TEXT_SIZE = "Encryptor.MaxAllowedCipherTextSize";

	public static final String PBE_ENCRYPTION_JCE_PROVIDER = "Encryptor.PBEEncryptionJCEProvider";
	public static final String PREFERRED_JCE_PROVIDER = "Encryptor.PreferredJCEProvider";
	public static final String CIPHER_TRANSFORMATION_IMPLEMENTATION = "Encryptor.CipherTransformation";
	public static final String CIPHERTEXT_USE_MAC = "Encryptor.CipherText.useMAC";
	public static final String PLAINTEXT_OVERWRITE = "Encryptor.PlainText.overwrite";
	public static final String IV_TYPE = "Encryptor.ChooseIVMethod";
	public static final String FIXED_IV = "Encryptor.fixedIV";
	public static final String COMBINED_CIPHER_MODES = "Encryptor.cipher_modes.combined_modes";
	public static final String ADDITIONAL_ALLOWED_CIPHER_MODES = "Encryptor.cipher_modes.additional_allowed";
	public static final String PRINT_PROPERTIES_WHEN_LOADED = "Security.printProperties";

	public static final String VALIDATION_PROPERTIES = "Validator.ConfigurationFile";
	public static final String ACCEPT_LENIENT_DATES = "Validator.AcceptLenientDates";
	public static final String XSS_PROPERTIES = "XSS.ConfigurationFile";
	public static final String XSS_PATTERN_KEY = "XSS.Pattern";
	public static final String XSS_PATTERN_ENCODED = "XSS.Pattern.encoded";

	public static final String ENCODER_IMPLEMENTATION = "Security.Encoder";
	public static final String ENCRYPTION_IMPLEMENTATION = "Security.Encryptor";
	public static final String INTRUSION_DETECTION_IMPLEMENTATION = "Security.IntrusionDetector";
	public static final String RANDOMIZER_IMPLEMENTATION = "Security.Randomizer";
	public static final String VALIDATOR_IMPLEMENTATION = "Security.Validator";
	public static final String DEFAULT_ENCODER_IMPLEMENTATION = "com.bosch.security.codecs.impl.DefaultEncoder";
	public static final String DEFAULT_ENCRYPTION_IMPLEMENTATION = "com.bosch.security.crypto.impl.DataEncryptor";
	public static final String DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION = "com.bosch.security.logger.impl.DefaultIntrusionDetector";
	public static final String DEFAULT_RANDOMIZER_IMPLEMENTATION = "com.bosch.security.random.impl.DefaultRandomizer";
	public static final String DEFAULT_VALIDATOR_IMPLEMENTATION = "com.bosch.security.validator.impl.DefaultValidator";

	private static final Map<String, Object> patternCache = new HashMap<String, Object>();
	private String resourceDirectory = "config"; //Default resource directory path if not specified..
	private static String customDirectory = System.getProperty("com.bosch.security.resources"); //Absolute path to the customDirectory

	/**
	 * Instantiates a new configuration.
	 */
	public DefaultSecurityConfiguration() 
	{
		try {
			loadConfiguration();
			this.setCipherXProperties();
		} catch( IOException e ) {
			logSpecial("Failed to load security configuration", e );
			throw new ConfigurationException("Failed to load security configuration", e);
		}
	}

	/**
	 * Instantiates a new configuration with the supplied properties.
	 * Warning - if the setResourceDirectory() method is invoked the properties will
	 * be re-loaded, replacing the supplied properties.
	 * @param properties
	 */
	public DefaultSecurityConfiguration(Properties properties) {
		super();
		this.properties = properties; 
		this.setCipherXProperties();
	}

	private void setCipherXProperties() {
		cipherXformFromSecurityProp = getSecurityProperty(CIPHER_TRANSFORMATION_IMPLEMENTATION, "AES/CBC/PKCS5Padding");
		cipherXformCurrent = cipherXformFromSecurityProp;
	}

	private Properties loadPropertiesFromStream(InputStream is, String name ) throws IOException {
		Properties config = new Properties();
		try {
			config.load(is);
			logSpecial("Loaded '" + name + "' properties file", null);
		} finally {
			if ( is != null ) {
				try { 
					is.close(); 
				} 
				catch(Exception e) {

				}
			}
		}
		return config;
	}

	/**
	 * Load configuration. Never prints properties.
	 * @throws java.io.IOException if the file is inaccessible
	 */
	protected void loadConfiguration() throws IOException 
	{
		try 
		{
			//First attempt file IO loading of properties
			logSpecial("Attempting to load " + RESOURCE_FILE + " via file I/O.");
			properties = loadPropertiesFromStream(getResourceStream(RESOURCE_FILE), RESOURCE_FILE);
		} 
		catch (Exception iae) 
		{
			//If file I/O loading fails, attempt classpath based loading next
			logSpecial("Loading " + RESOURCE_FILE + " via file I/O failed. Exception was: " + iae);
			logSpecial("Attempting to load " + RESOURCE_FILE + " via the classpath.");
			try {
				properties = loadConfigurationFromClasspath(RESOURCE_FILE);
			} 
			catch (Exception e) {				
				logSpecial(RESOURCE_FILE + " could not be loaded by any means. Fail.", e);
				throw new ConfigurationException(RESOURCE_FILE + " could not be loaded by any means. Fail.", e);
			}			
		}

		//If properties loaded properly above, get validation properties and merge them into the main properties
		if (properties != null) {

			String validationPropFileName = getSecurityProperty(VALIDATION_PROPERTIES, "validation.properties");
			Properties validationProperties = null;

			//clear any cached validation patterns so they can be reloaded from validation.properties
			patternCache.clear();

			try {
				logSpecial("Attempting to load " + validationPropFileName + " via file I/O.");
				validationProperties = loadPropertiesFromStream(getResourceStream(validationPropFileName), validationPropFileName);

			} catch (Exception iae) {
				logSpecial("Loading " + validationPropFileName + " via file I/O failed.");
				logSpecial("Attempting to load " + validationPropFileName + " via the classpath.");		
				try {
					validationProperties = loadConfigurationFromClasspath(validationPropFileName);
				} catch (Exception e) {				
					logSpecial(validationPropFileName + " could not be loaded by any means. fail.", e);
				}			
			}

			if (validationProperties != null) {
				Iterator<?> i = validationProperties.keySet().iterator();
				while( i.hasNext() ) {
					String key = (String)i.next();
					String value = validationProperties.getProperty(key);
					properties.put( key, value);
				}
			}
		}

		//If properties loaded properly above, get validation properties and merge them into the main properties
		if (properties != null) {

			String xssPropFileName = getSecurityProperty(XSS_PROPERTIES, "xss.properties");
			Properties xssProperties = null;

			//clear any cached validation patterns so they can be reloaded from validation.properties
			patternCache.clear();

			try {
				logSpecial("Attempting to load " + xssPropFileName + " via file I/O.");
				xssProperties = loadPropertiesFromStream(getResourceStream(xssPropFileName), xssPropFileName);

			} catch (Exception iae) {
				logSpecial("Loading " + xssPropFileName + " via file I/O failed.");
				logSpecial("Attempting to load " + xssPropFileName + " via the classpath.");		
				try {
					xssProperties = loadConfigurationFromClasspath(xssPropFileName);
				} catch (Exception e) {				
					logSpecial(xssPropFileName + " could not be loaded by any means. fail.", e);
				}			
			}

			//Add all the XSS patterns list in the property object as a single key.
			if (xssProperties != null) {
				Collection<Object> xssPatternList = xssProperties.values();
				if(!xssPatternList.isEmpty()) {
					properties.put(XSS_PATTERN_KEY, xssPatternList);
				}
			}
		}
	}	

	/**
	 * Get the resource stream.
	 * @param filename
	 * @return An {@code InputStream} associated with the specified file name as a resource stream.
	 * @throws IOException If the file cannot be found or opened for reading.
	 */
	public InputStream getResourceStream(String filename) throws IOException 
	{
		if (filename == null) {
			return null;
		}

		FileInputStream fileInputStream  = null;
		try {
			File f = getResourceFile(filename);
			if (f != null && f.exists()) {
				fileInputStream = new FileInputStream(f);
				return fileInputStream;
			}
		} 
		catch (Exception e) {
			if(fileInputStream!=null) {
				try { 
					fileInputStream.close(); 
				} 
				catch(Exception exception) {
					// Error while closing the file input stream.. 
				}	
			}
		}
		throw new FileNotFoundException();
	}

	@Override
	public File getResourceFile(String filename) 
	{
		logSpecial("Attempting to load " + filename + " as resource file via file I/O.");

		if (filename == null) {
			logSpecial("Failed to load properties via FileIO. Filename is null.");
			return null; // not found.
		}

		File f = null;
		f = new File(customDirectory, filename);
		if (customDirectory != null && f.canRead()) {
			logSpecial("Found in 'org.owasp.esapi.resources' directory: " + f.getAbsolutePath());
			return f;
		} else {
			logSpecial("Not found in 'org.owasp.esapi.resources' directory or file not readable: " + f.getAbsolutePath());
		}

		return null;
	}

	/**
	 * Used to load Security.properties from a variety of different classpath locations.
	 * @param fileName The properties file filename.
	 */
	private Properties loadConfigurationFromClasspath(String fileName) throws IllegalArgumentException 
	{
		Properties result = null;
		InputStream in = null;

		ClassLoader[] loaders = new ClassLoader[] {
				Thread.currentThread().getContextClassLoader(),
				ClassLoader.getSystemClassLoader(),
				getClass().getClassLoader() 
		};
		String[] classLoaderNames = {
				"current thread context class loader",
				"system class loader",
				"class loader for DefaultSecurityConfiguration class"
		};

		ClassLoader currentLoader = null;
		for (int i = 0; i < loaders.length; i++) {
			if (loaders[i] != null) 
			{
				currentLoader = loaders[i];
				try
				{
					//Root
					String currentClasspathSearchLocation = "/ (root)";
					in = loaders[i].getResourceAsStream(fileName);

					//Resource Directory 
					if (in == null) {
						currentClasspathSearchLocation = resourceDirectory + "/";
						in = currentLoader.getResourceAsStream(resourceDirectory + "/" + fileName);
					}

					//Resources 
					if (in == null) {
						currentClasspathSearchLocation = "resources/";
						in = currentLoader.getResourceAsStream("resources/" + fileName);
					}

					//Load the properties
					if (in != null) {
						result = new Properties();
						result.load(in); // Can throw IOException
						logSpecial("SUCCESSFULLY LOADED " + fileName + " via the CLASSPATH from '" +
								currentClasspathSearchLocation + "' using " + classLoaderNames[i] + "!");
						break;
					}
				} 
				catch (Exception e) {
					result = null;

				} 
				finally {
					try {
						in.close();
					} 
					catch (Exception e) {
					}
				}
			}
		}
		if (result == null) {
			throw new ConfigurationException("Failed to load " + RESOURCE_FILE + " as a classloader resource.");
		}
		return result;
	}

	@Override
	public String getEncoderImplementation() {
		return getSecurityProperty(ENCODER_IMPLEMENTATION, DEFAULT_ENCODER_IMPLEMENTATION);
	}

	@Override
	public String getEncryptionImplementation() {
		return getSecurityProperty(ENCRYPTION_IMPLEMENTATION, DEFAULT_ENCRYPTION_IMPLEMENTATION);
	}

	@Override
	public String getIntrusionDetectionImplementation() {
		return getSecurityProperty(INTRUSION_DETECTION_IMPLEMENTATION, DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION);
	}

	@Override
	public String getRandomizerImplementation() {
		return getSecurityProperty(RANDOMIZER_IMPLEMENTATION, DEFAULT_RANDOMIZER_IMPLEMENTATION);
	}

	@Override
	public String getValidationImplementation() {
		return getSecurityProperty(VALIDATOR_IMPLEMENTATION, DEFAULT_VALIDATOR_IMPLEMENTATION);
	}

	@Override
	public int getEncryptionKeyLength() {
		return getSecurityProperty(KEY_LENGTH, 256 );
	}

	@Override
	public String getEncryptionAlgorithm() {
		return getSecurityProperty(ENCRYPTION_ALGORITHM, "AES");
	}

	@Override
	public String getPBEEncryptionAlgorithm() {
		return getSecurityProperty(PBE_ENCRYPTION_ALGORITHM, "PBEWITHSHA256AND128BITAES-CBC-BC");
	}


	@Override
	public String getPBEEncryptionJCEProvider() {
		return getSecurityProperty(PBE_ENCRYPTION_JCE_PROVIDER, "org.bouncycastle.jce.provider.BouncyCastleProvider");
	}

	@Override
	public String getCipherTransformation() {
		assert cipherXformCurrent != null : "Current cipher transformation is null";
		return cipherXformCurrent;
	}

	@Override
	public boolean useMACforCipherText() {
		return getSecurityProperty(CIPHERTEXT_USE_MAC, true);
	}

	@Override
	public boolean overwritePlainText() {
		return getSecurityProperty(PLAINTEXT_OVERWRITE, true);
	}

	@Override
	public String getIVType()
	{
		String value = getSecurityProperty(IV_TYPE, "random");
		if (value.equalsIgnoreCase("fixed") || value.equalsIgnoreCase("random")) {
			return value;
		} 
		else {
			throw new ConfigurationException(value + " is illegal value for " + IV_TYPE +
					". Use 'random' (preferred) or 'fixed'.");
		}
	}

	@Override
	public String getFixedIV() {
		if ( getIVType().equalsIgnoreCase("fixed") ) {
			String ivAsHex = getSecurityProperty(FIXED_IV, ""); // No default
			if ( ivAsHex == null || ivAsHex.trim().equals("") ) {
				throw new ConfigurationException("Fixed IV requires property " +
						FIXED_IV + " to be set, but it is not.");
			}
			return ivAsHex;
		} else {
			throw new ConfigurationException("IV type not 'fixed' (set to '" +
					getIVType() + "'), so no fixed IV applicable.");
		}
	}

	@Override
	public String getHashAlgorithm() {
		return getSecurityProperty(HASH_ALGORITHM, "SHA-512");
	}

	@Override
	public int getHashIterations() {
		return getSecurityProperty(HASH_ITERATIONS, 1024);
	}

	@Override
	public String getCharacterEncoding() {
		return getSecurityProperty(CHARACTER_ENCODING, "UTF-8");
	}

	@Override
	public boolean getAllowMultipleEncoding() {
		return getSecurityProperty( ALLOW_MULTIPLE_ENCODING, false );
	}

	@Override
	public boolean getAllowMixedEncoding() {
		return getSecurityProperty( ALLOW_MIXED_ENCODING, false );
	}

	@Override
	public String getPreferredJCEProvider() {
		return properties.getProperty(PREFERRED_JCE_PROVIDER); // No default!
	}  

	@Override
	public List<String> getCombinedCipherModes(){
		List<String> empty = new ArrayList<String>();     // Default is empty list
		return getSecurityProperty(COMBINED_CIPHER_MODES, empty);
	}

	@Override
	public List<String> getAdditionalAllowedCipherModes(){
		List<String> empty = new ArrayList<String>();     // Default is empty list
		return getSecurityProperty(ADDITIONAL_ALLOWED_CIPHER_MODES, empty);
	}

	@Override
	public int getSaltLength() {
		return getSecurityProperty(SALT_LENGTH, 32 );
	}

	@Override
	public List<String> getDefaultCanonicalizationCodecs() {
		List<String> def = new ArrayList<String>();
		def.add( "com.bosch.security.codecs.HTMLEntityCodec" );
		def.add( "com.bosch.security.codecs.PercentCodec" );
		def.add( "com.bosch.security.codecs.JavaScriptCodec" );
		return getSecurityProperty(CANONICALIZATION_CODECS, def );
	}

	@Override
	public String getRandomAlgorithm() {
		return getSecurityProperty(RANDOM_ALGORITHM, "SHA1PRNG");
	}

	@Override
	public boolean getDisableIntrusionDetection() {
		String value = properties.getProperty( DISABLE_INTRUSION_DETECTION );
		if ("true".equalsIgnoreCase(value)) return true;
		return false;	// Default result
	}

	@Override
	public Threshold getQuota(String eventName) {
		int count = getSecurityProperty("IntrusionDetector." + eventName + ".count", 0);
		int interval =  getSecurityProperty("IntrusionDetector." + eventName + ".interval", 0);
		List<String> actions = new ArrayList<String>();
		String actionString = getSecurityProperty("IntrusionDetector." + eventName + ".actions", "");
		if (actionString != null) {
			String[] actionList = actionString.split(",");
			actions = Arrays.asList(actionList);
		}
		if ( count > 0 && interval > 0 && actions.size() > 0 ) {
			return new Threshold(eventName, count, interval, actions);
		}
		return null;
	}

	/**
	 * Returns a single pattern based upon key
	 *  @param key validation pattern name you'd like
	 *  @return if key exists, the associated validation pattern, null otherwise
	 */
	@Override
	public Pattern getValidationPattern(String key)
	{
		//Check if the compiled pattern already exist in cache. If yes, then return.
		if(patternCache.containsKey(key)){
			return (Pattern)patternCache.get(key);
		}

		//Get the key-value from the loaded property file.
		String value = getSecurityProperty( "Validator." + key, "" );
		if (value == null || value.equals("")) {
			return null;
		}

		//Compile a new pattern
		try {
			Pattern q = Pattern.compile(value.trim(),Pattern.CASE_INSENSITIVE);
			patternCache.put(key, q);
			return q;
		} catch ( PatternSyntaxException e ) {
			logSpecial( "SecurityConfiguration for " + key + " not a valid regex in *.properties. Returning null", null );
			return null;
		}
	}

	/**
	 * Returns a single pattern based upon key
	 *  @param key validation pattern name you'd like
	 *  @return if key exists, the associated validation pattern, null otherwise
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<Pattern> getXSSPatterns()
	{
		//Check if the compiled patterns already exist in cache. If yes, then return.
		if(patternCache.containsKey(XSS_PATTERN_KEY)){
			return (List<Pattern>)patternCache.get(XSS_PATTERN_KEY);
		}

		Collection<String> xssStrings = (Collection<String>)properties.get(XSS_PATTERN_KEY);
		if ( xssStrings == null  ||  xssStrings.isEmpty()) {
			logSpecial( "SecurityConfiguration for " + XSS_PATTERN_KEY + " not found in *.properties.", null );
			return null;
		}

		//Decode the xss pattern string
		List<String> xssDecodedStrings = null;
		boolean isPatternEncoded = getSecurityProperty(XSS_PATTERN_ENCODED, false);
		if(isPatternEncoded) {
			xssDecodedStrings = new ArrayList<String> ();
			for(String xssString : xssStrings) {
				try {
					xssDecodedStrings.add(new String(Base64.decodeBase64(xssString), "ISO-8859-1"));
				} catch (UnsupportedEncodingException e) {
					logSpecial( "UnsupportedEncodingException for " + XSS_PATTERN_KEY + "_" + xssString );
				}
			}
			xssStrings.clear();
			xssStrings = xssDecodedStrings;
		}

		//Compile a new pattern
		List<Pattern> xssPatterns = new ArrayList<Pattern>();
		for (String xssString : xssStrings) {
			try {
				xssPatterns.add(Pattern.compile(xssString.trim(),Pattern.CASE_INSENSITIVE));
			} catch ( PatternSyntaxException e ) {
				logSpecial("SecurityConfiguration for " + XSS_PATTERN_KEY + " not a valid regex in *.properties. Returning null", null );
				return null;
			}
		}

		patternCache.put(XSS_PATTERN_KEY, xssPatterns);
		return xssPatterns ;
	}

	@Override
	public boolean getLenientDatesAccepted() {
		return getSecurityProperty( ACCEPT_LENIENT_DATES, false);
	}

	@Override
	public int getMaxAllowedCipherTextSize() {
		return getSecurityProperty(MAX_ALLOWED_CIPHER_TEXT_SIZE, 1024);
	}

	protected String getSecurityProperty(String key, String def ) {
		String value = properties.getProperty(key);
		if ( value == null ) {
			logSpecial( "SecurityConfiguration for " + key + " not found in *.properties. Using default: " + def, null );
			return def;
		}
		return value;
	}

	protected boolean getSecurityProperty(String key, boolean def ) {
		String property = properties.getProperty(key);
		if ( property == null ) {
			logSpecial( "SecurityConfiguration for " + key + " not found in *.properties. Using default: " + def, null );
			return def;
		}
		if ( property.equalsIgnoreCase("true") || property.equalsIgnoreCase("yes" ) ) {
			return true;
		}
		if ( property.equalsIgnoreCase("false") || property.equalsIgnoreCase( "no" ) ) {
			return false;
		}
		logSpecial( "SecurityConfiguration for " + key + " not either \"true\" or \"false\" in *.properties. Using default: " + def, null );
		return def;
	}

	protected byte[] getSecurityPropertyEncoded(String key, byte[] def ) {
		String property = properties.getProperty(key);
		if ( property == null ) {
			logSpecial( "SecurityConfiguration for " + key + " not found in *.properties. Using default: " + def, null );
			return def;
		}
		return Base64.decodeBase64( property.trim() );
	}

	protected int getSecurityProperty(String key, int def ) {
		String property = properties.getProperty(key);
		if ( property == null ) {
			logSpecial( "SecurityConfiguration for " + key + " not found in Security.properties. Using default: " + def, null );
			return def;
		}
		try {
			return Integer.parseInt(property.trim());
		} catch( NumberFormatException e ) {
			logSpecial( "SecurityConfiguration for " + key + " not an integer in Security.properties. Using default: " + def, null );
			return def;
		}
	}

	protected List<String> getSecurityProperty(String key, List<String> def ) {
		String property = properties.getProperty( key );
		if ( property == null ) {
			logSpecial( "SecurityConfiguration for " + key + " not found in Security.properties. Using default: " + def, null );
			return def;
		}
		String[] parts = property.split(",");
		return Arrays.asList( parts );
	}

	protected boolean shouldPrintProperties() {
		return getSecurityProperty(PRINT_PROPERTIES_WHEN_LOADED, false);
	}

	protected Properties getSecurityProperties() {
		return properties;
	}

	/**
	 * Used to log errors to the console during the loading of the properties file itself. Can't use
	 * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
	 * {@code PrintStream} {@code System.out}.
	 * @param message The message to send to the console.
	 * @param e The error that occurred. (This value printed via {@code e.toString()}.)
	 */
	private void logSpecial(String message, Throwable e) {
		StringBuffer msg = new StringBuffer(message);
		if (e != null) {
			msg.append(" Exception was: ").append( e.toString() );
		}
		System.out.println( msg.toString() );
	}

	/**
	 * Used to log errors to the console during the loading of the properties file itself. Can't use
	 * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
	 * {@code PrintStream} {@code System.out}.
	 * @param message The message to send to the console.
	 */
	private void logSpecial(String message) {
		System.out.println(message);
	}

	@Override
	public boolean getLogEncodingRequired() {
		String value = properties.getProperty(LOG_ENCODING_REQUIRED);
		if ("false".equalsIgnoreCase(value)) {
			return false;
		}
		return true; // Default result
	}

}
