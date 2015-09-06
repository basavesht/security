package com.bosch.security.crypto;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.EnumSet;
import java.util.Iterator;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.errors.EncryptionException;
import com.bosch.security.logger.EventType;
import com.bosch.security.util.SecurityHandler;

/**
 * A {@code Serializable} interface representing the result of encrypting
 * plaintext and some additional information about the encryption algorithm,
 * the IV (if pertinent), and an optional Message Authentication Code (MAC). 
 */
public final class CipherText implements Serializable 
{	
	public  static final int cipherTextVersion = 20130830; 
	private static final long serialVersionUID = cipherTextVersion; // Format: YYYYMMDD

	private static final Logger logger = LoggerFactory.getLogger(CipherText.class);

	private CipherSpec cipherSpec_           = null;
	private byte[]     raw_ciphertext_       = null;
	private long       encryption_timestamp_ = 0;
	private byte[]     separate_mac_         = null;

	//CipherText attributes.
	private enum CipherTextFlags {
		ALGNAME, CIPHERMODE, PADDING, KEYSIZE, BLOCKSIZE, CIPHERTEXT, INITVECTOR
	}

	//Enumset of CipherText attributes.
	private final EnumSet<CipherTextFlags> allCtFlags =
			EnumSet.of(CipherTextFlags.ALGNAME,    CipherTextFlags.CIPHERMODE,
					CipherTextFlags.PADDING,    CipherTextFlags.KEYSIZE,
					CipherTextFlags.BLOCKSIZE,  CipherTextFlags.CIPHERTEXT,
					CipherTextFlags.INITVECTOR);

	//Enumset of CipherText attributes recieved from the CipherSpec.
	private final EnumSet<CipherTextFlags> fromCipherSpec =
			EnumSet.of(CipherTextFlags.ALGNAME,    CipherTextFlags.CIPHERMODE,
					CipherTextFlags.PADDING,    CipherTextFlags.KEYSIZE,
					CipherTextFlags.BLOCKSIZE);

	// How much we've collected so far. We start out with having collected nothing.
	private EnumSet<CipherTextFlags> progress = EnumSet.noneOf(CipherTextFlags.class);

	/**
	 * Default Constructor. Takes all the defaults from the security-config.properties, or
	 * default values from initial values from this class (when appropriate)
	 * when they are not set in ESAPI.properties.
	 */
	public CipherText() {
		cipherSpec_ = new CipherSpec();
		received(fromCipherSpec);
	}

	/**
	 * Construct from a {@code CipherSpec} object. Still needs to have
	 * {@link #setCiphertext(byte[])} or {@link #setIVandCiphertext(byte[], byte[])}
	 * called to be usable.
	 * @param cipherSpec The cipher specification to use.
	 */
	public CipherText(final CipherSpec cipherSpec) {
		cipherSpec_  = cipherSpec;
		received(fromCipherSpec);
		if ( cipherSpec.getIV() != null ) {
			received(CipherTextFlags.INITVECTOR);
		}
	}

	/**
	 * Construct from a {@code CipherSpec} object and the raw ciphertext.
	 * @param cipherSpec 
	 * @param cipherText 
	 * @throws EncryptionException
	 */
	public CipherText(final CipherSpec cipherSpec, byte[] cipherText) throws EncryptionException
	{
		cipherSpec_ = cipherSpec;
		setCiphertext(cipherText);
		received(fromCipherSpec);
		if (cipherSpec.getIV() != null ) {
			received(CipherTextFlags.INITVECTOR);
		}
	}

	/** Create a {@code CipherText} object from what is supposed to be a
	 *  portable serialized byte array
	 * @param bytes A byte array created via {@code CipherText.asPortableSerializedByteArray()}
	 * @return A {@code CipherText} object reconstructed from the byte array.
	 * @throws EncryptionException
	 */    
	public static CipherText fromPortableSerializedBytes(byte[] bytes) throws EncryptionException {
		CipherTextSerializer cts = new CipherTextSerializer(bytes);
		return cts.asCipherText();
	}

	/**
	 * Obtain the String representing the cipher transformation used to encrypt
	 * the plaintext.
	 * @return The cipher transformation name used to encrypt the plaintext
	 * 		   resulting in this ciphertext.
	 */
	public String getCipherTransformation() {
		return cipherSpec_.getCipherTransformation();
	}

	/**
	 * Obtain the name of the cipher algorithm used for encrypting the plaintext.
	 * @return The name as the cryptographic algorithm 
	 */
	public String getCipherAlgorithm() {
		return cipherSpec_.getCipherAlgorithm();
	}

	/**
	 * Retrieve the key size used with the cipher algorithm that was used to
	 * encrypt data to produce this ciphertext.
	 * @return The key size in bits.
	 */
	public int getKeySize() {
		return cipherSpec_.getKeySize();
	}

	/**
	 * Retrieve the block size (in bytes!) of the cipher used for encryption.
	 * (Note: If an IV is used, this will also be the IV length.)
	 * @return The block size in bytes.
	 */
	public int getBlockSize() {
		return cipherSpec_.getBlockSize();
	}

	/**
	 * Get the name of the cipher mode used to encrypt some plaintext.
	 * @return The name of the cipher mode used to encrypt the plaintext
	 */
	public String getCipherMode() {
		return cipherSpec_.getCipherMode();
	}

	/**
	 * Get the name of the padding scheme used to encrypt some plaintext.
	 * @return The name of the padding scheme 
	 */
	public String getPaddingScheme() {
		return cipherSpec_.getPaddingScheme();
	}

	/**
	 * Return the initialization vector (IV) used to encrypt the plaintext
	 * if applicable.
	 * @return	The IV is returned if the cipher mode used to encrypt the
	 * 			plaintext was not "ECB".
	 */
	public byte[] getIV() {
		if ( isCollected(CipherTextFlags.INITVECTOR) ) {
			return cipherSpec_.getIV();
		} else {
			logger.error(EventType.SECURITY_FAILURE.getEvent() + " {}", "IV not set yet; unable to retrieve; returning null");
			return null;
		}
	}

	/** 
	 * Return true if the cipher mode used requires an IV. Usually this will
	 * be true unless ECB mode (which should be avoided whenever possible) is
	 * used.
	 */
	public boolean requiresIV() {
		return cipherSpec_.requiresIV();
	}

	/**
	 * Get the raw ciphertext byte array resulting from encrypting some
	 * plaintext.
	 * @return A copy of the raw ciphertext as a byte array.
	 */
	public byte[] getRawCipherText() {
		if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
			byte[] copy = new byte[ raw_ciphertext_.length ];
			System.arraycopy(raw_ciphertext_, 0, copy, 0, raw_ciphertext_.length);
			return copy;
		} else {
			logger.error(EventType.SECURITY_FAILURE.getEvent() + " {}", "Raw ciphertext not set yet; unable to retrieve; returning null");
			return null;
		}
	}

	/**
	 * Get number of bytes in raw ciphertext. Zero is returned if ciphertext has not
	 * yet been stored.
	 * @return The number of bytes of raw ciphertext; 0 if no raw ciphertext has been stored.
	 */
	public int getRawCipherTextByteLength() {
		if ( raw_ciphertext_ != null ) {
			return raw_ciphertext_.length;
		} else {
			return 0;
		}
	}

	/**
	 * Return a base64-encoded representation of the raw ciphertext alone.
	 */
	public String getBase64EncodedRawCipherText() {
		return SecurityHandler.encoder().encodeForBase64(getRawCipherText(),false);
	}


	/**
	 * Return this {@code CipherText} object as a portable (i.e., network byte
	 * ordered) serialized byte array. 
	 * @return A network byte-ordered serialized representation of this object.
	 * @throws EncryptionException
	 */   
	public byte[] asPortableSerializedByteArray() throws EncryptionException {
		if (!collectedAll()) {
			String msg = "Can't serialize this CipherText object yet as not " +
					"all mandatory information has been collected";
			throw new EncryptionException("Can't serialize incomplete ciphertext info", msg);
		}
		return new CipherTextSerializer(this).asSerializedByteArray();
	}

	/**
	 * Set the raw ciphertext.
	 * @param ciphertext    The raw ciphertext.
	 * @throws EncryptionException  Thrown if the MAC has already been computed
	 *              via {@link #computeAndStoreMAC(SecretKey)}.
	 */
	public void setCiphertext(byte[] ciphertext) throws EncryptionException
	{
		if (!macComputed()) {
			if ( ciphertext == null || ciphertext.length == 0 ) {
				throw new EncryptionException("Encryption faled; no ciphertext",
						"Ciphertext may not be null or 0 length!");
			}
			if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
				logger.debug(EventType.SECURITY_FAILURE.getEvent() + " {}", "Raw ciphertext was already set; resetting.");
			}
			raw_ciphertext_ = new byte[ ciphertext.length ];
			CryptoHelper.copyByteArray(ciphertext, raw_ciphertext_);
			received(CipherTextFlags.CIPHERTEXT);
			setEncryptionTimestamp();
		} else {
			String logMsg = "Programming error: Attempt to set ciphertext after MAC already computed.";
			logger.error(EventType.SECURITY_FAILURE.getEvent() + " {}", logMsg);
			throw new EncryptionException("MAC already set; cannot store new raw ciphertext", logMsg);
		}
	}



	/** Get stored time stamp representing when data was encrypted. */
	public long getEncryptionTimestamp() {
		return encryption_timestamp_;
	}

	/**
	 * Set the encryption timestamp to the current system time as determined by
	 * {@code System.currentTimeMillis()}, but only if it has not been previously
	 * set. That is, this method ony has an effect the first time that it is
	 * called for this object.
	 */
	private void setEncryptionTimestamp() {
		if ( encryption_timestamp_ != 0 ) {
			logger.debug(EventType.EVENT_FAILURE.getEvent() + " {}", "Attempt to reset non-zero " +
					"CipherText encryption timestamp to current time!");
		}
		encryption_timestamp_ = System.currentTimeMillis();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder( "CipherText: " );
		String creationTime = (( getEncryptionTimestamp() == 0) ? "No timestamp available" :
			(new Date(getEncryptionTimestamp())).toString());
		int n = getRawCipherTextByteLength();
		String rawCipherText = (( n > 0 ) ? "present (" + n + " bytes)" : "absent");
		String mac = (( separate_mac_ != null ) ? "present" : "absent");
		sb.append("Creation time: ").append(creationTime);
		sb.append(", raw ciphertext is ").append(rawCipherText);
		sb.append(", MAC is ").append(mac).append("; ");
		sb.append( cipherSpec_.toString() );
		return sb.toString();
	}

	@Override 
	public boolean equals(Object other) {
		boolean result = false;
		if ( this == other )
			return true;
		if ( other == null )
			return false;
		if ( other instanceof CipherText) {
			CipherText that = (CipherText)other;
			if ( this.collectedAll() && that.collectedAll() ) {
				result = (that.canEqual(this) &&
						this.cipherSpec_.equals(that.cipherSpec_) &&
						CryptoHelper.arrayCompare(this.raw_ciphertext_, that.raw_ciphertext_) &&
						CryptoHelper.arrayCompare(this.separate_mac_, that.separate_mac_) &&
						this.encryption_timestamp_ == that.encryption_timestamp_ );
			} else {
				logger.debug(EventType.EVENT_FAILURE.getEvent() + " {}", "CipherText.equals(): Cannot compare two " + "CipherText objects that are not complete, and therefore immutable!");
				logger.info(EventType.EVENT_FAILURE.getEvent() + " {}", "This CipherText: " + this.collectedAll() + ";" + "other CipherText: " + that.collectedAll());
				logger.info(EventType.EVENT_FAILURE.getEvent() + " {}", "CipherText.equals(): Progress comparison: " + ((this.progress == that.progress) ? "Same" : "Different"));
				logger.info(EventType.EVENT_FAILURE.getEvent() + " {}", "CipherText.equals(): Status this: " + this.progress + "; status other CipherText object: " + that.progress);
				return false;
			}
		}
		return result;
	}

	@Override 
	public int hashCode() 
	{
		if ( this.collectedAll() ) {
			logger.info(EventType.EVENT_FAILURE.getEvent() + " {}", "CipherText.hashCode(): Cannot compute " + "hachCode() of incomplete CipherText object; object not immutable- " + "returning 0.");
			return 0;
		}

		StringBuilder sb = new StringBuilder();
		sb.append( cipherSpec_.hashCode() );
		sb.append( encryption_timestamp_ );
		String raw_ct = null;
		String mac = null;
		try {
			raw_ct = new String(raw_ciphertext_, "UTF-8");
			mac = new String( ((separate_mac_ != null) ? separate_mac_ : new byte[] { }), "UTF-8");
		} catch(UnsupportedEncodingException ex) {
			raw_ct = new String(raw_ciphertext_);
			mac = new String( ((separate_mac_ != null) ? separate_mac_ : new byte[] { }));
		}
		sb.append( raw_ct );
		sb.append( mac );
		return sb.toString().hashCode();
	}

	/**
	 * Needed for correct definition of equals for general classes.
	 * (Technically not needed for 'final' classes though like this class
	 * though; this will just allow it to work in the future should we
	 * decide to allow * sub-classing of this class.)
	 * </p><p>
	 * See {@link http://www.artima.com/lejava/articles/equality.html}
	 * for full explanation.
	 * </p>
	 */
	protected boolean canEqual(Object other) {
		return (other instanceof CipherText);
	}

	/**
	 * Return true if the MAC has already been computed (i.e., not null).
	 */
	private boolean macComputed() {
		return (separate_mac_ != null);
	}

	/**
	 * Return true if we've collected all the required pieces; otherwise false.
	 */
	private boolean collectedAll() {
		EnumSet<CipherTextFlags> ctFlags = null;
		if (requiresIV() ) {
			ctFlags = allCtFlags;
		} else {
			EnumSet<CipherTextFlags> initVector = EnumSet.of(CipherTextFlags.INITVECTOR);
			ctFlags = EnumSet.complementOf(initVector);
		}
		boolean result = progress.containsAll(ctFlags);  
		return result;
	}

	/** Check if we've collected a specific flag type.
	 * @param flag  The flag type; e.g., {@code CipherTextFlags.INITVECTOR}, etc.
	 * @return  Return true if we've collected a specific flag type; otherwise false.
	 */
	private boolean isCollected(CipherTextFlags flag) {
		return progress.contains(flag);
	}

	/**
	 * Add the flag to the set of what we've already collected.
	 * @param flag  The flag type to be added; e.g., {@code CipherTextFlags.INITVECTOR}.
	 */
	private void received(CipherTextFlags flag) {
		progress.add(flag);
	}

	/**
	 * Add all the flags from the specified set to that we've collected so far.
	 * @param ctSet A {@code EnumSet<CipherTextFlags>} containing all the flags
	 *              we wish to add.
	 */
	private void received(EnumSet<CipherTextFlags> ctSet) {
		Iterator<CipherTextFlags> it = ctSet.iterator();
		while ( it.hasNext() ) {
			received( it.next() );
		}
	}

	/**
	 * Set the encryption timestamp to the time stamp specified by the parameter.
	 * This method is intended for use only by {@code CipherTextSerializer}.
	 * @param timestamp 
	 */ 
	void setEncryptionTimestamp(long timestamp) {
		assert timestamp > 0 : "Timestamp must be greater than zero.";
		if ( encryption_timestamp_ == 0 ) {   
			logger.debug(EventType.EVENT_FAILURE.getEvent() + " {}", "Attempt to reset non-zero " + "CipherText encryption timestamp to " + new Date(timestamp) + "!");
		}
		encryption_timestamp_ = timestamp;
	}
}
