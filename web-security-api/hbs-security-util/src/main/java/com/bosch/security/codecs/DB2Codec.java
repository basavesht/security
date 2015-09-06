package com.bosch.security.codecs;

/**
 * Implementation of the Codec interface for DB2 strings. 
 * This function will only protect you from SQLi in limited situations.
 */
public class DB2Codec extends Codec
{
   @Override
	public String encodeCharacter(char[] immune, Character c) {

		if (c.charValue() == '\'')
			return "\'\'";

		if (c.charValue() == ';')
			return ".";

		return "" + c;
	}

   @Override
	public Character decodeCharacter(PushbackString input) 
   {
		input.mark();
		
		Character first = input.next();
		if (first == null) {
			input.reset();
			return null;
		}

		//If this is not an encoded character, return null
		if (first.charValue() != '\'') {
			input.reset();
			return null;
		}

		Character second = input.next();
		if (second == null) {
			input.reset();
			return null;
		}

		//If this is not an encoded character, return null
		if (second.charValue() != '\'') {
			input.reset();
			return null;
		}

		return (Character.valueOf('\''));
	}
}