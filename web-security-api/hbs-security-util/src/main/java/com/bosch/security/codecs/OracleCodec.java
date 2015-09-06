package com.bosch.security.codecs;

/**
 * Implementation of the Codec interface for Oracle strings. This function will only protect you from SQLi in the case of user data
 * bring placed within an Oracle quoted string such as:
 * select * from table where user_name='  USERDATA    ';
 */
public class OracleCodec extends Codec
{
	/**
	 * Encodes ' to ''
     * @param immune
     */
	@Override
	public String encodeCharacter(char[] immune, Character c ) {
		if ( c.charValue() == '\'' )
        	return "\'\'";
        return ""+c;
	}
	
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * Formats all are legal '' decodes to '
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
		if (first.charValue() != '\'' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		if ( second == null ) {
			input.reset();
			return null;
		}
		
		//If this is not an encoded character, return null
		if ( second.charValue() != '\'' ) {
			input.reset();
			return null;
		}
		return( Character.valueOf( '\'' ) );
	}

}