package com.bosch.security.crypto.impl;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.codecs.Hex;
import com.bosch.security.crypto.CipherSpec;
import com.bosch.security.crypto.CipherText;
import com.bosch.security.crypto.CryptoHelper;
import com.bosch.security.crypto.Encryptor;
import com.bosch.security.crypto.PlainText;
import com.bosch.security.crypto.SecurityProviderLoader;
import com.bosch.security.errors.ConfigurationException;
import com.bosch.security.errors.EncryptionException;
import com.bosch.security.logger.EventType;
import com.bosch.security.util.SecurityHandler;

/**
 * Reference implementation of the {@code Encryptor} interface. This implementation
 * layers on the JCE provided cryptographic package. Algorithms used are
 * configurable in the {@code security-config.properties} file. The main property
 * controlling the selection of this class is {@code bosch.security.Encryptor}. Most of
 * the other encryption related properties have property names that start with
 * the string "Encryptor.".
 */
public final class DataEncryptor implements Encryptor
{
	private static volatile Encryptor singletonInstance;
	private static Logger logger = LoggerFactory.getLogger(DataEncryptor.class);

	//Default variables with values (Used only if values not configured in external property file).
	private static boolean initialized = false;
	private static SecretKeySpec secretKeySpec = null; 
	private static String encryptAlgorithm = "AES";
	private static int encryptionKeyLength = 128;
	private static String encoding = "UTF-8"; 
	private static String hashAlgorithm = "SHA-256";
	private static int hashIterations = 1024;
	private static boolean overwritePlaintextInMemory = true;

	//Use this string for user messages for EncryptionException when decryption fails to prevent information leakage
	private static final String DECRYPTION_FAILED = "Decryption failed; see logs for details.";

	//Singleton instance [Invoked from SecurityHandler]
	public static Encryptor getInstance() throws EncryptionException {
		if ( singletonInstance == null ) {
			synchronized ( DataEncryptor.class ) {
				if ( singletonInstance == null ) {
					singletonInstance = new DataEncryptor();
				}
			}
		}
		return singletonInstance;
	}

	//Load the preferred JCE provider if one has been specified else leave as is.
	static {
		try {
			SecurityProviderLoader.loadPreferredJCEProvider();
		} catch (NoSuchProviderException ex) {
			logger.error(EventType.SECURITY_FAILURE.getEvent() + "{}" + "{}", "JavaEncryptor failed to load preferred JCE provider.", ex);
			throw new ExceptionInInitializerError(ex);
		}
		setupAlgorithms();
	}

	/**
	 * Private Constructor for {@code EncryptorImpl}, called by {@code getInstance()}.
	 * @throws EncryptionException if can't construct this object for some reason.
	 * 					Original exception will be attached as the 'cause'.
	 */
	private DataEncryptor() throws EncryptionException
	{
		synchronized(DataEncryptor.class) {
			if (!initialized ) 
			{
				// Set up secretKeySpec for use for symmetric encryption and decryption
				try {
					SecretKey secretKey = CryptoHelper.generateSecretKey(encryptAlgorithm, encryptionKeyLength);
					secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), encryptAlgorithm);
				} catch (Exception e) {
					throw new EncryptionException("Encryption failure", "Error creating Encryptor instance", e);
				}

				// Mark everything as initialized.
				initialized = true;
			}
		}
	}

	/**
	 * Get all the algorithms we will be using from security-config.properties.
	 * Refer the security configuration for more details.
	 */
	private static void setupAlgorithms() {
		encryptAlgorithm = SecurityHandler.securityConfiguration().getEncryptionAlgorithm();
		hashAlgorithm = SecurityHandler.securityConfiguration().getHashAlgorithm();
		hashIterations = SecurityHandler.securityConfiguration().getHashIterations();
		encoding = SecurityHandler.securityConfiguration().getCharacterEncoding();
		encryptionKeyLength = SecurityHandler.securityConfiguration().getEncryptionKeyLength();
	}

	@Override
	public String hash(String plaintext, String salt) throws EncryptionException {
		return hash(plaintext, salt, hashIterations);
	}

	@Override
	public String hash(String plaintext, String salt, int iterations) throws EncryptionException {
		byte[] bytes = null;
		try 
		{
			//Create a instance of MessageDigest using the hashing algorithm..
			MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
			digest.reset();
			digest.update(salt.getBytes(encoding));
			digest.update(plaintext.getBytes(encoding));

			//Rehash a number of times (iterations) to help strengthen weak passwords
			bytes = digest.digest();
			for (int i = 0; i < iterations; i++) {
				digest.reset();
				bytes = digest.digest(bytes);
			}

			//Encode using Base64 and return.
			String encoded = SecurityHandler.encoder().encodeForBase64(bytes,false);
			return encoded;
		} 
		catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Internal error", "Can't find hash algorithm " + hashAlgorithm, e);
		}
		catch (UnsupportedEncodingException ex) {
			throw new EncryptionException("Internal error", "Can't find encoding for " + encoding, ex);
		}
	}

	@Override
	public CipherText encrypt(PlainText plaintext) throws EncryptionException {
		return encrypt(secretKeySpec, plaintext);
	}

	@Override
	public CipherText encrypt(SecretKey key, PlainText plain) throws EncryptionException
	{
		//Assert the input...
		if (key == null ) {
			throw new IllegalArgumentException("(Master) encryption key arg may not be null");
		}
		if (plain == null ) {
			throw new IllegalArgumentException("PlainText may arg not be null");
		}

		//Extract the byte[] from PlainText instance.
		byte[] plainTextAsBytes = plain.asBytes();

		//Encrypt ..
		boolean success = false;
		String xform = null;
		int keySize = key.getEncoded().length * 8;
		try 
		{
			xform = SecurityHandler.securityConfiguration().getCipherTransformation();
			String[] parts = xform.split("/");
			assert parts.length == 3 : "Malformed cipher transformation: " + xform;
			String cipherMode = parts[1];

			// This way we can prevent modes like OFB and CFB where the IV should never be repeated with the same encryption key
			if (!CryptoHelper.isAllowedCipherMode(cipherMode) ) {
				throw new EncryptionException("Encryption failure: invalid cipher mode ( " + cipherMode + ") for encryption",
						"Encryption failure: Cipher transformation " + xform + " specifies invalid " +
								"cipher mode " + cipherMode);
			}

			//Cipher is not thread-safe so we create one locally
			Cipher encrypter = Cipher.getInstance(xform);
			String cipherAlg = encrypter.getAlgorithm();

			//Check if algorithm mentioned in SecretKey is same as that being used for Cipher object.
			String skeyAlg = key.getAlgorithm();
			if ( !( cipherAlg.startsWith( skeyAlg + "/") || cipherAlg.equals(skeyAlg))) {
				logger.info(EventType.SECURITY_FAILURE.getEvent() + " {}", "Encryption mismatch between cipher algorithm (" +
						cipherAlg + ") and SecretKey algorithm (" + skeyAlg + "). Cipher will use algorithm " + cipherAlg);
			}

			//Using cipher mode that supports *both* confidentiality *and* authenticity
			boolean preferredCipherMode = CryptoHelper.isCombinedCipherMode(cipherMode);
			SecretKey encKey = null;
			if (preferredCipherMode ) {
				encKey = key;
			}
			else {
				throw new EncryptionException("Encryption failure: invalid cipher mode ( " + cipherMode + ") for encryption",
						"Encryption failure: Cipher transformation " + xform + " specifies invalid " +
								"cipher mode " + cipherMode);
			}

			//Most of the preferred cipher modes requires IV (Initialization Vector)
			byte[] ivBytes = null;
			CipherSpec cipherSpec = new CipherSpec(encrypter, keySize);
			if (cipherSpec.requiresIV()) {
				String ivType = SecurityHandler.securityConfiguration().getIVType();
				if (ivType.equalsIgnoreCase("random")) {
					ivBytes = SecurityHandler.randomizer().getRandomBytes(encrypter.getBlockSize());
				} else if (ivType.equalsIgnoreCase("fixed")) {
					String fixedIVAsHex = SecurityHandler.securityConfiguration().getFixedIV();
					ivBytes = Hex.decode(fixedIVAsHex);
				} else {
					throw new ConfigurationException("Property Encryptor.ChooseIVMethod must be set to 'random' or 'fixed'");
				}

				//Create IV Paramter specs and accordingly update CipherSpec instance.
				IvParameterSpec ivSpec = null;
				ivSpec = new IvParameterSpec(ivBytes);
				cipherSpec.setIV(ivBytes);

				//Initialise Cipher with OpMode, key and algorithm parameter specs.
				encrypter.init(Cipher.ENCRYPT_MODE, encKey, ivSpec);
			} else {
				encrypter.init(Cipher.ENCRYPT_MODE, encKey);
			}

			//Encrypt data (byte[])
			byte[] rawEncryptedData = encrypter.doFinal(plainTextAsBytes);

			//Convert to CipherText object.
			CipherText ciphertext = new CipherText(cipherSpec, rawEncryptedData);

			success = true;	
			return ciphertext;
		} 
		catch (InvalidKeyException ike) {
			throw new EncryptionException("Encryption failure: Invalid key exception.",
					"Requested key size: " + keySize + "bits greater than 128 bits. Must install unlimited strength crypto extension from Sun: " +
							ike.getMessage(), ike);
		} 
		catch (ConfigurationException cex) {
			throw new EncryptionException("Encryption failure: Configuration error. Details in log.", "Key size mismatch or unsupported IV method. " +
					"Check encryption key size vs. ESAPI.EncryptionKeyLength or Encryptor.ChooseIVMethod property.", cex);
		} 
		catch (InvalidAlgorithmParameterException e) {
			throw new EncryptionException("Encryption failure (invalid IV)",
					"Encryption problem: Invalid IV spec: " + e.getMessage(), e);
		} 
		catch (IllegalBlockSizeException e) {
			throw new EncryptionException("Encryption failure (no padding used; invalid input size)",
					"Encryption problem: Invalid input size without padding (" + xform + "). " + e.getMessage(), e);
		} 
		catch (BadPaddingException e) {
			throw new EncryptionException("Encryption failure",
					"[Note: Should NEVER happen in encryption mode.] Encryption problem: " + e.getMessage(), e);
		} 
		catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Encryption failure (unavailable cipher requested)",
					"Encryption problem: specified algorithm in cipher xform " + xform + " not available: " + e.getMessage(), e);
		} 
		catch (NoSuchPaddingException e) {
			throw new EncryptionException("Encryption failure (unavailable padding scheme requested)",
					"Encryption problem: specified padding scheme in cipher xform " + xform + " not available: " + e.getMessage(), e);
		} 
		finally {
			if (success && overwritePlaintextInMemory) {
				plain.overwrite();
			}
		}
	}

	@Override
	public PlainText decrypt(CipherText ciphertext) throws EncryptionException {
		return decrypt(secretKeySpec, ciphertext);
	}

	@Override
	public PlainText decrypt(SecretKey key, CipherText ciphertext) throws EncryptionException, IllegalArgumentException
	{
		// Pre-Validation..
		if (key == null ) {
			throw new IllegalArgumentException("SecretKey arg may not be null");
		}
		if (ciphertext == null ) {
			throw new IllegalArgumentException("Ciphertext may arg not be null");
		}

		//Validate cipher mode.
		if (!CryptoHelper.isAllowedCipherMode(ciphertext.getCipherMode()) ) {
			throw new EncryptionException(DECRYPTION_FAILED, "Invalid cipher mode " + ciphertext.getCipherMode() + " not permitted for decryption or encryption operations.");
		}

		PlainText plaintext = null;
		try 
		{			
			//Create a cipher instance..
			Cipher decrypter = Cipher.getInstance(ciphertext.getCipherTransformation());

			//Validate CipherMode..
			boolean preferredCipherMode = CryptoHelper.isCombinedCipherMode(ciphertext.getCipherMode() );
			SecretKey encKey = null;
			if (preferredCipherMode) {
				encKey = key;
			} 
			else {
				throw new EncryptionException("Encryption failure: invalid cipher mode ( " + ciphertext.getCipherMode() + ") for encryption",
						"Encryption failure: Cipher transformation " + ciphertext.getCipherTransformation() + " specifies invalid " +
								"cipher mode " + ciphertext.getCipherMode()); 
			}

			//Most of the cipher mode requires IV(Intialization Vector). Initialise the cipher with OpMode, Key and Algorithm Parameter specs ..
			if (ciphertext.requiresIV()) {
				decrypter.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(ciphertext.getIV()));
			} else {
				decrypter.init(Cipher.DECRYPT_MODE, encKey);
			}

			//Decrypt raw bytes - Final
			byte[] rawDecryptedData = decrypter.doFinal(ciphertext.getRawCipherText());
			plaintext = new PlainText(rawDecryptedData);
		} 
		catch (InvalidKeyException ike) {
			throw new EncryptionException(DECRYPTION_FAILED, "Must install JCE Unlimited Strength Jurisdiction Policy Files from Sun", ike);
		} 
		catch (NoSuchAlgorithmException e) {
			throw new EncryptionException(DECRYPTION_FAILED, "Invalid algorithm for available JCE providers - " +
					ciphertext.getCipherTransformation() + ": " + e.getMessage(), e);
		} 
		catch (NoSuchPaddingException e) {
			throw new EncryptionException(DECRYPTION_FAILED, "Invalid padding scheme (" +
					ciphertext.getPaddingScheme() + ") for cipher transformation " + ciphertext.getCipherTransformation() +
					": " + e.getMessage(), e);
		} 
		catch (InvalidAlgorithmParameterException e) {
			throw new EncryptionException(DECRYPTION_FAILED, "Decryption problem: " + e.getMessage(), e);
		} 
		catch (IllegalBlockSizeException e) {
			throw new EncryptionException(DECRYPTION_FAILED, "Decryption problem: " + e.getMessage(), e);
		} 
		catch (BadPaddingException e) {			
			throw new EncryptionException(DECRYPTION_FAILED, "Decryption problem: " + e.getMessage(), e);
		}
		finally {

		}
		return plaintext;
	}

}
