package com.bosch.security.crypto;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.logger.EventType;

/**
 * A class representing plaintext (versus ciphertext) as related to
 * cryptographic systems.  This class embodies UTF-8 byte-encoding to
 * translate between byte arrays and {@code String}s. Once constructed, this
 * object is immutable.
 * @see CipherText
 */
public final class PlainText implements Serializable 
{
	private static final long serialVersionUID = -2321793988762605303L;
	private static Logger logger = LoggerFactory.getLogger(PlainText.class);
	private byte[] rawBytes = null;

	/**
	 * Construct a {@code PlainText} object from a {@code String}.
	 * @param str	The {@code String} that is converted to a UTF-8 encoded
	 * 				byte array to create the {@code PlainText} object.
	 * @throws IllegalArgumentException	If {@code str} argument is null.
	 */
	public PlainText(String str) {
		try {
			if (str == null ) {
				throw new IllegalArgumentException("String for plaintext may not be null!");
			}
			rawBytes = str.getBytes("UTF-8");
		} 
		catch (UnsupportedEncodingException e) {
			logger.error(EventType.EVENT_FAILURE.getEvent() + " {}" + " {}" , "PlainText(String) CTOR failed: Can't find UTF-8 byte-encoding!", e);
			throw new RuntimeException("Can't find UTF-8 byte-encoding!", e);
		}
	}

	/**
	 * Construct a {@code PlainText} object from a {@code byte} array.
	 * @param b	The {@code byte} array used to create the {@code PlainText}
	 * 			object.
	 */
	public PlainText(byte[] b) {
		assert b != null : "Byte array representing plaintext cannot be null.";
		rawBytes = new byte[ b.length ]; //Allo 0 length array for empty strings..
		System.arraycopy(b, 0, rawBytes, 0, b.length);
	}

	/**
	 * Convert the {@code PlainText} object to a UTF-8 encoded {@code String}.
	 * @return	A {@code String} representing the {@code PlainText} object.
	 */
	public String toString() {
		try {
			return new String(rawBytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			logger.error(EventType.EVENT_FAILURE.getEvent() + " {}" + " {}" , "PlainText.toString() failed: Can't find UTF-8 byte-encoding!", e);
			throw new RuntimeException("Can't find UTF-8 byte-encoding!", e);
		}
	}

	/**
	 * Convert the {@code PlainText} object to a byte array.
	 * @return	A byte array representing the {@code PlainText} object.
	 */
	public byte[] asBytes() {
		byte[] bytes = new byte[ rawBytes.length ];
		System.arraycopy(rawBytes, 0, bytes, 0, rawBytes.length);
		return bytes;
	}

	/**
	 * Return the length of the UTF-8 encoded byte array representing this
	 * object. Note that if this object was constructed with the constructor
	 * {@code PlainText(String str)}, then this length might not necessarily
	 * agree with {@code str.length()}.
	 * 
	 * @return	The length of the UTF-8 encoded byte array representing this
	 * 			object.
	 */
	public int length() {
		return rawBytes.length;
	}

	/**
	 * First overwrite the bytes of plaintext with the character '*'.
	 * This is like purging the data from the memory..
	 */
	public void overwrite() {
		CryptoHelper.overwrite(rawBytes);
	}

	@Override 
	public boolean equals(Object anObject) {

		if (this == anObject ) return true;
		if (anObject == null ) return false;
		boolean result = false;
		if (anObject instanceof PlainText ) {
			PlainText that = (PlainText)anObject;
			result = (this.toString().equals(that.toString()));
		}
		return result;
	}

	@Override 
	public int hashCode() {
		return this.toString().hashCode();
	}
}