package com.bosch.security.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.errors.EncryptionException;
import com.bosch.security.logger.EventType;
import com.bosch.security.util.ByteConversionUtil;

/**
 * Helper class to assist with programming language and platform independent
 * serialization of {@link CipherText} objects. The serialization is done in
 * network-byte order which is the same as big-endian byte order.
 * <p>
 * This serialization scheme is documented in
 * <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-ciphertext-serialization.pdf">
 * <code>Format of Portable Serialization of org.owasp.esapi.crypto.CipherText Objects</code>.</a>
 * Other serialization schemes may be desirable and could be supported (notably, RFC 5083 - Cryptographic
 * Message Syntax (CMS) Authenticated-Enveloped-Data Content Type, or CMS' predecessor,
 * PKCS#7 (RFC 2315)), but these serialization schemes are by comparison very complicated,
 * and do not have extensive support for the various implementation languages which ESAPI
 * supports. (Perhaps wishful thinking that other ESAPI implementations such as
 * ESAPI for .NET, ESAPI for C, ESAPI for C++, etc. will all support a single, common
 * serialization technique so they could exchange encrypted data.)
 */
public class CipherTextSerializer 
{
	private static final Logger logger = LoggerFactory.getLogger(CipherTextSerializer.class);

	private CipherText cipherText_ = null;

	public CipherTextSerializer(CipherText cipherTextObj) {
		if ( cipherTextObj == null ) {
			throw new IllegalArgumentException("CipherText object must not be null.");
		}
		assert cipherTextObj != null : "CipherText object must not be null.";      
		cipherText_ = cipherTextObj;
	}

	/**
	 * Given byte array in network byte order (i.e., big-endian order), convert
	 * it so that a {@code CipherText} can be constructed from it.
	 * @param cipherTextSerializedBytes A serialized {@code CipherText} object
	 *          with the bytes in network byte order.
	 * @throws EncryptionException Thrown if a valid {@code CipherText} object
	 *          cannot be reconstructed from the byte array.
	 */
	public CipherTextSerializer(byte[] cipherTextSerializedBytes)
			throws EncryptionException 
	{
		cipherText_ = convertToCipherText(cipherTextSerializedBytes);
	}

	/** Return this {@code CipherText} object as a specialized, portable
	 *  serialized byte array.
	 * @return A serialization of this object. Note that this is <i>not</i> the
	 * Java serialization.
	 */
	public byte[] asSerializedByteArray() {
		long timestamp = cipherText_.getEncryptionTimestamp();
		String cipherXform = cipherText_.getCipherTransformation();
		assert cipherText_.getKeySize() < Short.MAX_VALUE :
			"Key size too large. Max is " + Short.MAX_VALUE;
		short keySize = (short) cipherText_.getKeySize();
		assert cipherText_.getBlockSize() < Short.MAX_VALUE :
			"Block size too large. Max is " + Short.MAX_VALUE;
		short blockSize = (short) cipherText_.getBlockSize();
		byte[] iv = cipherText_.getIV();
		assert iv.length < Short.MAX_VALUE :
			"IV size too large. Max is " + Short.MAX_VALUE;
		short ivLen = (short) iv.length;
		byte[] rawCiphertext = cipherText_.getRawCipherText();
		int ciphertextLen = rawCiphertext.length;
		assert ciphertextLen >= 1 : "Raw ciphertext length must be >= 1 byte.";  
		byte[] serializedObj = computeSerialization(timestamp,
				cipherXform,
				keySize,
				blockSize,
				ivLen,
				iv,
				ciphertextLen,
				rawCiphertext
				);

		return serializedObj;
	}

	/**
	 * Return the actual {@code CipherText} object.
	 * @return The {@code CipherText} object that we are serializing.
	 */
	public CipherText asCipherText() {
		assert cipherText_ != null;
		return cipherText_;
	}

	/**
	 * Take all the individual elements that make of the serialized ciphertext
	 * format and put them in order and return them as a byte array.
	 * @param kdfInfo	Info about the KDF... which PRF and the KDF version {@link #asCipherText()}.
	 * @param timestamp	Timestamp when the data was encrypted. Intended to help
	 * 					facilitate key change operations and nothing more. If it is meaningless,
	 * 					then the expectations are just that the recipient should ignore it. Mostly
	 * 					intended when encrypted data is kept long term over a period of many
	 * 					key change operations.
	 * @param cipherXform	Details of how the ciphertext was encrypted. The format used
	 * 						is the same as used by {@code javax.crypto.Cipher}, namely,
	 * 						"cipherAlg/cipherMode/paddingScheme".
	 * @param keySize	The key size used for encrypting. Intended for cipher algorithms
	 * 					supporting multiple key sizes such as triple DES (DESede) or
	 * 					Blowfish.
	 * @param blockSize	The cipher block size. Intended to support cipher algorithms
	 * 					that support variable block sizes, such as Rijndael.
	 * @param ivLen		The length of the IV.
	 * @param iv		The actual IV (initialization vector) bytes.
	 * @param ciphertextLen	The length of the raw ciphertext.
	 * @param rawCiphertext	The actual raw ciphertext itself
	 * @param macLen	The length of the MAC (message authentication code).
	 * @param mac		The MAC itself.
	 * @return	A byte array representing the serialized ciphertext.
	 */
	private byte[] computeSerialization(long timestamp,
			String cipherXform, short keySize,
			short blockSize,
			short ivLen, byte[] iv,
			int ciphertextLen, byte[] rawCiphertext
			)
	{
		debug("computeSerialization: timestamp = " + new Date(timestamp));
		debug("computeSerialization: cipherXform = " + cipherXform);
		debug("computeSerialization: keySize = " + keySize);
		debug("computeSerialization: blockSize = " + blockSize);
		debug("computeSerialization: ivLen = " + ivLen);
		debug("computeSerialization: ciphertextLen = " + ciphertextLen);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		writeLong(baos, timestamp);
		String[] parts = cipherXform.split("/");
		assert parts.length == 3 : "Malformed cipher transformation";
		writeString(baos, cipherXform); // Size of string is prepended to string
		writeShort(baos, keySize);
		writeShort(baos, blockSize);
		writeShort(baos, ivLen);
		if ( ivLen > 0 ) baos.write(iv, 0, iv.length);
		writeInt(baos, ciphertextLen);
		baos.write(rawCiphertext, 0, rawCiphertext.length);
		return baos.toByteArray();
	}

	private void writeString(ByteArrayOutputStream baos, String str) {
		byte[] bytes;
		try {
			assert str != null && str.length() > 0;
			bytes = str.getBytes("UTF8");
			assert bytes.length < Short.MAX_VALUE : "writeString: String exceeds max length";
			writeShort(baos, (short)bytes.length);
			baos.write(bytes, 0, bytes.length);
		} catch (UnsupportedEncodingException e) {
			logger.error(EventType.EVENT_FAILURE.getEvent() + " {}", "Ignoring caught UnsupportedEncodingException " +
					"converting string to UTF8 encoding. Results suspect. Corrupt rt.jar????");
		}
	}

	private String readString(ByteArrayInputStream bais, short sz)
			throws NullPointerException, IOException
	{
		byte[] bytes = new byte[sz];
		int ret = bais.read(bytes, 0, sz);
		assert ret == sz : "readString: Failed to read " + sz + " bytes.";
		return new String(bytes, "UTF8");
	}

	private void writeShort(ByteArrayOutputStream baos, short s) {
		byte[] shortAsByteArray = ByteConversionUtil.fromShort(s);
		assert shortAsByteArray.length == 2;
		baos.write(shortAsByteArray, 0, 2);
	}

	private short readShort(ByteArrayInputStream bais)
			throws NullPointerException, IndexOutOfBoundsException
	{
		byte[] shortAsByteArray = new byte[2];
		int ret = bais.read(shortAsByteArray, 0, 2);
		assert ret == 2 : "readShort: Failed to read 2 bytes.";
		return ByteConversionUtil.toShort(shortAsByteArray);
	}

	private void writeInt(ByteArrayOutputStream baos, int i) {
		byte[] intAsByteArray = ByteConversionUtil.fromInt(i);
		baos.write(intAsByteArray, 0, 4);
	}

	private int readInt(ByteArrayInputStream bais)
			throws NullPointerException, IndexOutOfBoundsException
	{
		byte[] intAsByteArray = new byte[4];
		int ret = bais.read(intAsByteArray, 0, 4);
		assert ret == 4 : "readInt: Failed to read 4 bytes.";
		return ByteConversionUtil.toInt(intAsByteArray);
	}

	private void writeLong(ByteArrayOutputStream baos, long l) {
		byte[] longAsByteArray = ByteConversionUtil.fromLong(l);
		assert longAsByteArray.length == 8;
		baos.write(longAsByteArray, 0, 8);
	}

	private long readLong(ByteArrayInputStream bais)
			throws NullPointerException, IndexOutOfBoundsException
	{
		byte[] longAsByteArray = new byte[8];
		int ret = bais.read(longAsByteArray, 0, 8);
		assert ret == 8 : "readLong: Failed to read 8 bytes.";
		return ByteConversionUtil.toLong(longAsByteArray);
	}

	/** Convert the serialized ciphertext byte array to a {@code CipherText}
	 * object.
	 * @param cipherTextSerializedBytes	The serialized ciphertext as a byte array.
	 * @return The corresponding {@code CipherText} object.
	 * @throws EncryptionException	Thrown if the byte array data is corrupt or
	 * 				there are version mismatches, etc.
	 */
	private CipherText convertToCipherText(byte[] cipherTextSerializedBytes) throws EncryptionException 
	{
		try
		{
			assert cipherTextSerializedBytes != null : "cipherTextSerializedBytes cannot be null.";
			assert cipherTextSerializedBytes.length > 0 : "cipherTextSerializedBytes must be > 0 in length.";
			ByteArrayInputStream bais = new ByteArrayInputStream(cipherTextSerializedBytes);

			long timestamp = readLong(bais);
			debug("convertToCipherText: timestamp = " + new Date(timestamp));

			short strSize = readShort(bais);
			debug("convertToCipherText: length of cipherXform = " + strSize);

			String cipherXform = readString(bais, strSize);
			debug("convertToCipherText: cipherXform = " + cipherXform);

			String[] parts = cipherXform.split("/");
			assert parts.length == 3 : "Malformed cipher transformation";

			String cipherMode = parts[1];
			if ( ! CryptoHelper.isAllowedCipherMode(cipherMode) ) {
				String msg = "Cipher mode " + cipherMode + " is not an allowed cipher mode";
				throw new EncryptionException(msg, msg);
			}

			short keySize = readShort(bais);
			debug("convertToCipherText: keySize = " + keySize);

			short blockSize = readShort(bais);
			debug("convertToCipherText: blockSize = " + blockSize);

			short ivLen = readShort(bais);
			debug("convertToCipherText: ivLen = " + ivLen);

			byte[] iv = null;
			if ( ivLen > 0 ) {
				iv = new byte[ivLen];
				bais.read(iv, 0, iv.length);
			}

			int ciphertextLen = readInt(bais);
			if(ciphertextLen < 0 || CryptoHelper.exceedsMaxSizeLimit(ciphertextLen)){
				logger.error("convertToCipherText: Invalid cipher text length found : {} " , Integer.toString(ciphertextLen));
				throw new EncryptionException ("convertToCipherText: Invalid cipher text length found ", "Invalid cipher text length found");
			}

			byte[] rawCiphertext = new byte[ciphertextLen];
			bais.read(rawCiphertext, 0, rawCiphertext.length);

			CipherSpec cipherSpec = new CipherSpec(cipherXform, keySize);
			cipherSpec.setBlockSize(blockSize);
			cipherSpec.setIV(iv);
			debug("convertToCipherText: CipherSpec: " + cipherSpec);
			CipherText ct = new CipherText(cipherSpec);
			if ( ! (ivLen > 0 && ct.requiresIV()) ) {
				throw new EncryptionException("convertToCipherText: Mismatch between IV length and cipher mode.",
						"Possible tampering of serialized ciphertext?");
			}
			ct.setCiphertext(rawCiphertext);
			ct.setEncryptionTimestamp(timestamp);
			return ct;
		} 
		catch(EncryptionException ex) {
			throw new EncryptionException("Cannot deserialize byte array into CipherText object",
					"Cannot deserialize byte array into CipherText object",
					ex);
		} 
		catch (IOException e) {
			throw new EncryptionException("Cannot deserialize byte array into CipherText object",
					"Cannot deserialize byte array into CipherText object", e);
		}
	}

	private void debug(String msg) {
		if (logger.isDebugEnabled() ) {
			//logger.debug(EventType.EVENT_SUCCESS.getEvent() + " {}", msg);
		}
	}
}
