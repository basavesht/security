package com.bosch.security.codecs;

/**
 * Implementation of the Codec interface for '\' encoding from Unix command shell.
 */
public class UnixCodec extends Codec {

	/**
	 * Returns backslash-encoded character
     * @param immune
     */
	@Override
	public String encodeCharacter( char[] immune, Character c ) 
	{
		char ch = c.charValue();
		
		//Check for immune characters
		if ( containsCharacter( ch, immune ) ) {
			return ""+ch;
		}
		
		//Check for alphanumeric characters
		String hex = Codec.getHexForNonAlphanumeric( ch );
		if ( hex == null ) {
			return ""+ch;
		}
		
        return "\\" + c;
	}
	 
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * <p>
	 * Formats all are legal both upper/lower case:
	 *   \x - all special characters 
	 */
	public Character decodeCharacter( PushbackString input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		//If this is not an encoded character, return null
		if ( first.charValue() != '\\' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		return second;
	}

}