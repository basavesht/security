package com.bosch.security.crypto;

import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Hashtable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.logger.EventType;
import com.bosch.security.util.SecurityHandler;

/** 
 * This class provides a generic static method that loads a
 * {@code java.security.Provider} either by some generic name
 * (i.e., {@code Provider.getName()}) or by a fully-qualified class name.
 * It is intended to be called dynamically by an application to add a
 * specific JCE provider at runtime.
 */
public class SecurityProviderLoader  
{
	private static Logger logger = LoggerFactory.getLogger(SecurityProviderLoader.class);

	// Load the table with known providers.
	private static Hashtable<String, String> jceProviders;
	static {
		jceProviders = new Hashtable<String,String>();
		jceProviders.put("BC", "org.bouncycastle.jce.provider.BouncyCastleProvider");
		jceProviders.put("SunJCE", "com.sun.crypto.provider.SunJCE");
		jceProviders.put("IBMJCE", "com.ibm.crypto.provider.IBMJCE");
	}

	/** 
	 * This methods adds a provider to the {@code SecurityManager}
	 * either by some generic name or by the class name. 
	 * </p><p>
	 * The following generic JCE provider names are built-in:
	 * <ul>
	 * <li>SunJCE</li>
	 * <li>IBMJCE [for WebSphere]</li>
	 * <li>BC [i.e., Bouncy Castle]</li>
	 * </ul>
	 * @param algProvider Name of the JCE algorithm provider.
	 * @param pos         The preference position (starting at 1) that the
	 *                    caller would like for this provider. -1 for the last position
	 * @return The actual preference position at which the provider was added,
	 *         or -1 if the provider was not added because it is already
	 *         installed.
	 * @exception NoSuchProviderException - thrown if the provider class
	 *         could not be loaded or added to the {@code SecurityManager} or
	 *         any other reason for failure.
	 */
	public static int insertProviderAt(String algProvider, int pos) throws NoSuchProviderException
	{
		Class<?> providerClass = null;
		String clzName = null;
		Provider cryptoProvider = null;
		assert (pos == -1 || pos >= 1) : "Position pos must be -1 or integer >= 1";
		try 
		{
			//AlgProvider look like a class name.
			if (algProvider.indexOf('.') != -1) {
				clzName = algProvider;
			} 
			else if (jceProviders.containsKey(algProvider)) {
				clzName = jceProviders.get(algProvider);
			} 
			else {
				throw new NoSuchProviderException("Unable to locate Provider class for " +
						"provider " + algProvider + ". Try using fully qualified class name " +
						"or check provider name for typos. Builtin provider names are: " +
						jceProviders.toString());
			}

			//Create the preferred JCE provider instance...
			providerClass = Class.forName(clzName);
			cryptoProvider = (Provider)providerClass.newInstance();

			// Note that Security.insertProviderAt() can throw a SecurityException if a Java SecurityManager is
			// installed and application doesn't have appropriate permissions in policy file.
			int ret;
			if (pos == -1 ) {      //Special case: Means place _last_.
				ret = Security.addProvider(cryptoProvider);
			} else {
				ret = Security.insertProviderAt(cryptoProvider, pos);
			}

			//Verify whether provider added or not.
			if (ret == -1) {
				String msg = "JCE provider '" + algProvider + "' already loaded";
				if (pos == -1) {
					logger.debug(EventType.SECURITY_SUCCESS.getEvent() + " {}", msg);
				} else {
					//JCE provider loaded at some other position (non-compliance)
					logger.info(EventType.SECURITY_FAILURE.getEvent() + " {}", msg);
				}
			} else {
				logger.info(EventType.SECURITY_AUDIT.getEvent() + " {}", "Successfully loaded preferred JCE provider " + algProvider + " at position " + pos);
			}
			return ret;
		} 
		catch(SecurityException ex) {
			logger.info(EventType.SECURITY_FAILURE.getEvent() + " {}", "Failed to load preferred JCE provider " + algProvider + " at position " + pos, ex);
			throw ex;
		} 
		catch(Exception ex) {
			logger.error(EventType.EVENT_FAILURE.getEvent() + " {}", "Failed to insert failed crypto " + " provider " + algProvider + " at position " + pos, ex);
			throw new NoSuchProviderException("Failed to insert crypto " + " provider for " + algProvider + "; exception msg: " + ex.toString());
		}
	}

	/**
	 * Load the preferred JCE provider as defined in the security-config.properties 
	 * file. If this property is null (i.e., unset) or set to an empty string, 
	 * then no JCE provider is inserted at the "preferred" position and thus 
	 * the Java VM continues to use whatever the default it was using for 
	 * this (generally specified in the file {@code $JAVA_HOME/jre/security/java.security}).
	 * @return The actual preference position at which the provider was added
	 * @exception NoSuchProviderException
	 */
	public static int loadPreferredJCEProvider() throws NoSuchProviderException
	{
		String prefJCEProvider = SecurityHandler.securityConfiguration().getPreferredJCEProvider();
		try {
			if (prefJCEProvider == null || prefJCEProvider.trim().length() == 0) {
				logger.info(EventType.SECURITY_AUDIT.getEvent() + " {}", "No Encryptor.PreferredJCEProvider specified.");
				return -1;  // Unchanged; it is, whatever it is.
			} else {
				return insertProviderAt(prefJCEProvider, 1);
			}
		} catch (NoSuchProviderException ex) {
			String msg = "failed to load *preferred* " + "JCE crypto provider, " + prefJCEProvider;
			logger.info(EventType.SECURITY_AUDIT.getEvent() + " {}", msg);
			logger.error(EventType.SECURITY_FAILURE.getEvent() + " {}", msg);
			throw ex;
		}
	}

	/**
	 * Load the preferred JCE provider for PBEEncryption mode as defined in the security-config.properties 
	 * file. If this property is null (i.e., unset) or set to an empty string, 
	 * then no JCE provider is inserted at the "preferred" position and thus 
	 * the Java VM continues to use whatever the default it was using for 
	 * this (generally specified in the file {@code $JAVA_HOME/jre/security/java.security}).
	 * @return The actual preference position at which the provider was added
	 * @exception NoSuchProviderException
	 */
	public static int loadPreferredPBEEncryptionJCEProvider() throws NoSuchProviderException
	{
		String prefJCEPBEEncryptionProvider = SecurityHandler.securityConfiguration().getPBEEncryptionJCEProvider();
		try {
			if (prefJCEPBEEncryptionProvider == null || prefJCEPBEEncryptionProvider.trim().length() == 0) {
				logger.info(EventType.SECURITY_AUDIT.getEvent() + " {}", "No Encryptor.PBEEncryptionJCEProvider specified.");
				return -1;  // Unchanged; it is, whatever it is.
			} else {
				return insertProviderAt(prefJCEPBEEncryptionProvider, 1);
			}
		} catch (NoSuchProviderException ex) {
			String msg = "failed to load *preferred* " + "JCE crypto provider, " + prefJCEPBEEncryptionProvider;
			logger.info(EventType.SECURITY_AUDIT.getEvent() + " {}", msg);
			logger.error(EventType.SECURITY_FAILURE.getEvent() + " {}", msg);
			throw ex;
		}
	}
}
