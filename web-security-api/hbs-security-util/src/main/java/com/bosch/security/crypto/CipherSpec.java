package com.bosch.security.crypto;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;

import com.bosch.security.util.NullSafe;
import com.bosch.security.util.SecurityHandler;
import com.bosch.security.util.StringUtilities;

/**
 * Specifies all the relevant configuration data needed in constructing and
 * using a {@link javax.crypto.Cipher} except for the encryption key.
 * </p><p>
 */
public final class CipherSpec implements Serializable 
{
	private static final long serialVersionUID = 5473257625203796494L;

	private String  cipher_xform_   = SecurityHandler.securityConfiguration().getCipherTransformation();
	private int     keySize_        = SecurityHandler.securityConfiguration().getEncryptionKeyLength();
	private int     blockSize_      = 16;   // In bytes! i.e., 128 bits!!!
	private byte[]  iv_             = null;
	private enum CipherTransformationComponent { ALG, MODE, PADDING } // Cipher transformation component. Format is ALG/MODE/PADDING

	/**
	 * Constructor that explicitly sets everything.
	 * @param cipherXform	The cipher transformation
	 * @param keySize		The key size (in bits).
	 * @param blockSize		The block size (in bytes).
	 * @param iv			The initialization vector. Null if not applicable.
	 */
	public CipherSpec(String cipherXform, int keySize, int blockSize, final byte[] iv) {
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
		setBlockSize(blockSize);
		setIV(iv);
	}

	/**
	 * Constructor that sets everything but IV.
	 * @param cipherXform	The cipher transformation
	 * @param keySize		The key size (in bits).
	 * @param blockSize		The block size (in bytes).
	 */
	public CipherSpec(String cipherXform, int keySize, int blockSize) {
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
		setBlockSize(blockSize);
	}

	/**
	 * Constructor that sets everything but block size and IV
	 * @param cipherXform	The cipher transformation
	 * @param keySize		The key size (in bits).
	 */
	public CipherSpec(String cipherXform, int keySize) {
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
	}

	/** 
	 * Constructor that sets everything except block size.
	 * @param cipherXform	The cipher transformation
	 * @param keySize		The key size (in bits).
	 * @param iv			The initialization vector. Null if not applicable.
	 */
	public CipherSpec(String cipherXform, int keySize, final byte[] iv) {
		setCipherTransformation(cipherXform);
		setKeySize(keySize);
		setIV(iv);
	}

	/** 
	 * Constructor that sets everything except for the cipher key size and possibly
	 * the IV.
	 * @param cipher
	 */
	public CipherSpec(final Cipher cipher) {
		setCipherTransformation(cipher.getAlgorithm(), true);
		setBlockSize(cipher.getBlockSize());
		if (cipher.getIV() != null ) {
			setIV(cipher.getIV());
		}
	}

	/** Constructor that sets everything.
	 * @param cipher
	 * @param keySize
	 */
	public CipherSpec(final Cipher cipher, int keySize) {
		this(cipher);
		setKeySize(keySize);
	}

	/** Constructor that sets only the IV and uses defaults for everything else. 
	 * @param iv
	 */
	public CipherSpec(final byte[] iv) {
		setIV(iv);
	}

	/**
	 * Default Constructor. Creates a cipher specification for 128-bit cipher
	 * transformation of "AES/CBC/PKCS5Padding" and a {@code null} IV.
	 */
	public CipherSpec() {
		// All defaults
	}

	/**
	 * Set the cipher transformation for this {@code CipherSpec}.
	 * @param cipherXform	The cipher transformation string; e.g., "DESede/CBC/PKCS5Padding".
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec setCipherTransformation(String cipherXform) {
		setCipherTransformation(cipherXform, false);
		return this;
	}

	/**
	 * Set the cipher transformation for this {@code CipherSpec}. This is only
	 * used by the Constructor {@code CipherSpec(Cipher)} and {@code CipherSpec(Cipher, int)}.
	 * @param cipherXform
	 * @param fromCipher If true, the cipher transformation was set via
	 * 					 {@code Cipher.getAlgorithm()} which may only return the
	 * 					 actual algorithm. In that case we check and if all 3 parts
	 * 					 were not specified, then we specify the parts that were
	 * 					 based on "ECB" as the default cipher mode and "NoPadding"
	 * 					 as the default padding scheme.
	 * @return	This current {@code CipherSpec} object.
	 */
	private CipherSpec setCipherTransformation(String cipherXform, boolean fromCipher)
	{
		if (!StringUtilities.notNullOrEmpty(cipherXform, true) ) {	
			throw new IllegalArgumentException("Cipher transformation may not be null or empty string (after trimming whitespace).");
		}

		int parts = cipherXform.split("/").length;
		assert (!fromCipher ? (parts == 3) : true) : "Malformed cipherXform (" + cipherXform + "); must have form: \"alg/mode/paddingscheme\"";

		if (fromCipher && (parts != 3)  ) {
			if ( parts == 1 ) {
				cipherXform += "/ECB/NoPadding";
			} else if (parts == 2) {
				cipherXform += "/NoPadding";
			} else if (parts == 3) {
				;	// Do nothing - shown only for completeness.
			} else {
				throw new IllegalArgumentException("Cipher transformation '" +
						cipherXform + "' must have form \"alg/mode/paddingscheme\"");
			}
		} else if ( !fromCipher && parts != 3 ) {
			throw new IllegalArgumentException("Malformed cipherXform (" + cipherXform +
					"); must have form: \"alg/mode/paddingscheme\"");
		}
		assert cipherXform.split("/").length == 3 : "Implementation error setCipherTransformation()";
		this.cipher_xform_ = cipherXform;
		return this;
	}

	/**
	 * Get the cipher transformation.
	 * @return	The cipher transformation {@code String}.
	 */
	public String getCipherTransformation() {
		return cipher_xform_;
	}

	/**
	 * Set the key size for this {@code CipherSpec}.
	 * @param keySize	The key size, in bits. Must be positive integer.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec setKeySize(int keySize) {
		assert keySize > 0 : "keySize must be > 0; keySize=" + keySize;
		this.keySize_ = keySize;
		return this;
	}

	/**
	 * Retrieve the key size, in bits.
	 * @return	The key size, in bits, is returned.
	 */
	public int getKeySize() {
		return keySize_;
	}

	/**
	 * Set the block size for this {@code CipherSpec}.
	 * @param blockSize	The block size, in bytes. Must be positive integer.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec setBlockSize(int blockSize) {
		assert blockSize > 0 : "blockSize must be > 0; blockSize=" + blockSize;
		this.blockSize_ = blockSize;
		return this;
	}

	/**
	 * Retrieve the block size, in bytes.
	 * @return	The block size, in bytes, is returned.
	 */
	public int getBlockSize() {
		return blockSize_;
	}

	/**
	 * Retrieve the cipher algorithm.
	 * @return	The cipher algorithm.
	 */
	public String getCipherAlgorithm() {
		return getFromCipherXform(CipherTransformationComponent.ALG);
	}

	/**
	 * Retrieve the cipher mode.
	 * @return	The cipher mode.
	 */
	public String getCipherMode() {
		return getFromCipherXform(CipherTransformationComponent.MODE);
	}

	/**
	 * Retrieve the cipher padding scheme.
	 * @return	The padding scheme is returned.
	 */
	public String getPaddingScheme() {
		return getFromCipherXform(CipherTransformationComponent.PADDING);
	}

	/**
	 * Retrieve the initialization vector (IV).
	 * @return	The IV as a byte array.
	 */
	public byte[] getIV() {
		return iv_;
	}

	/**
	 * Set the initialization vector (IV).
	 * @param iv	The byte array to set as the IV. A copy of the IV is saved.
	 * 				This parameter is ignored if the cipher mode does not
	 * 				require an IV.
	 * @return		This current {@code CipherSpec} object.
	 */
	public CipherSpec setIV(final byte[] iv) {
		assert requiresIV() && (iv != null && iv.length != 0) : "Required IV cannot be null or 0 length";
		if ( iv != null ) {	// Allow null IV for ECB mode.
			iv_ = new byte[ iv.length ];
			CryptoHelper.copyByteArray(iv, iv_);
		}
		return this;
	}

	/**
	 * Return true if the cipher mode requires an IV.
	 * @return True if the cipher mode requires an IV, otherwise false.
	 * */
	public boolean requiresIV() {
		String cm = getCipherMode();
		if ( "ECB".equalsIgnoreCase(cm) ) {
			return false;
		}
		return true;
	}

	/**
	 * Split the current cipher transformation and return the requested part. 
	 * @param component The component of the cipher transformation to return.
	 * @return The cipher algorithm, cipher mode, or padding, as requested.
	 */
	private String getFromCipherXform(CipherTransformationComponent component) {
		int part = component.ordinal();
		String[] parts = getCipherTransformation().split("/");
		assert parts.length == 3 : "Invalid cipher transformation: " + getCipherTransformation();	
		return parts[part];
	}

	/**
	 * Override {@code Object.toString()} to provide something more useful.
	 * @return A meaningful string describing this object.
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("CipherSpec: ");
		sb.append( getCipherTransformation() ).append("; keysize= ").append( getKeySize() );
		sb.append(" bits; blocksize= ").append( getBlockSize() ).append(" bytes");
		byte[] iv = getIV();
		String ivLen = null;
		if ( iv != null ) {
			ivLen = "" + iv.length;	// Convert length to a string
		} else {
			ivLen = "[No IV present (not set or not required)]";
		}
		sb.append("; IV length = ").append( ivLen ).append(" bytes.");
		return sb.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object other) {
		boolean result = false;
		if ( this == other )
			return true;
		if ( other == null )
			return false;
		if ( other instanceof CipherSpec) {
			CipherSpec that = (CipherSpec)other;
			result = (NullSafe.equals(this.cipher_xform_, that.cipher_xform_) &&
					this.keySize_ == that.keySize_ &&
					this.blockSize_ == that.blockSize_ &&
					CryptoHelper.arrayCompare(this.iv_, that.iv_) );
		}
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		StringBuilder sb = new StringBuilder();
		sb.append( getCipherTransformation() );
		sb.append( "" + getKeySize() );
		sb.append( "" + getBlockSize() );
		byte[] iv = getIV();
		if ( iv != null && iv.length > 0 ) {
			String ivStr = null;
			try {
				ivStr = new String(iv, "UTF-8");
			}
			catch(UnsupportedEncodingException ex) {
				ivStr = new String(iv); // Should never happen..
			}
			sb.append( ivStr );
		}
		return sb.toString().hashCode();
	}
}
