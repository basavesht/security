package com.bosch.security.codecs;

import java.io.UnsupportedEncodingException;
import java.util.Set;

import com.bosch.security.util.CollectionsUtil;

/**
 * Implementation of the Codec interface for percent encoding (aka URL encoding).
 */
public class PercentCodec extends Codec
{
	private static final String ALPHA_NUMERIC_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static final String RFC3986_NON_ALPHANUMERIC_UNRESERVED_STR = "-._~";
	private static final boolean ENCODED_NON_ALPHA_NUMERIC_UNRESERVED = true;
	private static final String UNENCODED_STR = ALPHA_NUMERIC_STR +
		(ENCODED_NON_ALPHA_NUMERIC_UNRESERVED ? "" : RFC3986_NON_ALPHANUMERIC_UNRESERVED_STR);
	private static final Set<Character> UNENCODED_SET = CollectionsUtil.strToUnmodifiableSet(UNENCODED_STR);

	/**
	 * Convinence method to encode a string into UTF-8.
	 * by the Java spec and should never throw this exception.
	 * @param str the string to encode
	 * @return str encoded in UTF-8 as bytes.
	 * @throws IllegalStateException
	 */
	private static byte[] toUtf8Bytes(String str)
	{
		try {
			return str.getBytes("UTF-8");
		}
		catch(UnsupportedEncodingException e) {
			throw new IllegalStateException("The Java spec requires UTF-8 support.", e);
		}
	}

	/**
	 * Append the two upper case hex characters for a byte.
	 * @param sb The string buffer to append to.
	 * @param b The byte to hexify
	 * @return sb with the hex characters appended.
	 */
	private static StringBuilder appendTwoUpperHex(StringBuilder sb, int b)
	{
		if(b < Byte.MIN_VALUE || b > Byte.MAX_VALUE)
			throw new IllegalArgumentException("b is not a byte (was " + b + ')');
		b &= 0xFF;
		if(b<0x10)
			sb.append('0');
		return sb.append(Integer.toHexString(b).toUpperCase());
	}

	/**
	 * Encode a character for URLs
	 * @param immune characters not to encode
	 * @param c character to encode
	 * @return the encoded string representing c
	 */
	public String encodeCharacter( char[] immune, Character c )
	{
		String cStr = String.valueOf(c.charValue());
		byte[] bytes;
		StringBuilder sb;

		if(UNENCODED_SET.contains(c))
			return cStr;

		bytes = toUtf8Bytes(cStr);
		sb = new StringBuilder(bytes.length * 3);
		for(byte b : bytes)
			appendTwoUpperHex(sb.append('%'), b);
		return sb.toString();
	}

	/** 
	 * Formats all are legal both upper/lower case
	 * @param input encoded character using percent characters (such as URL encoding)
	 */
	@Override
	public Character decodeCharacter(PushbackString input) 
	{
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}

		//If this is not an encoded character, return null
		if (first != '%' ) {
			input.reset();
			return null;
		}

		//Search for exactly 2 hex digits following
		StringBuilder sb = new StringBuilder();
		for ( int i=0; i<2; i++ ) {
			Character c = input.nextHex();
			if ( c != null ) sb.append( c );
		}
		if ( sb.length() == 2 ) {
			try {
				//Parse the hex digit and create a character
				int i = Integer.parseInt(sb.toString(), 16);
				if (Character.isValidCodePoint(i)) {
					return (char) i;
				}
			} catch( NumberFormatException ignored ) { }
		}
		input.reset();
		return null;
	}
}
