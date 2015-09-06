package com.bosch.security.codecs;

/**
 * Implementation of the Codec interface for backslash encoding in JavaScript.
 */
public class JavaScriptCodec extends Codec 
{
	/**
	 * Returns backslash encoded numeric format. Does not use backslash character escapes
	 * such as, \" or \' as these may cause parsing problems. For example, if a javascript
	 * attribute, such as onmouseover, contains a \" that will close the entire attribute and
	 * allow an attacker to inject another script attribute.
	 *
	 * @param immune
	 */
	@Override
	public String encodeCharacter(char[] immune,Character c)
	{
		//Check for immune characters
		if ( containsCharacter(c, immune ) ) {
			return ""+c;
		}

		//Check for alphanumeric characters
		String hex = Codec.getHexForNonAlphanumeric(c);
		if ( hex == null ) {
			return ""+c;
		}

		//Encode up to 256 with \\xHH
		String temp = Integer.toHexString(c);
		if ( c < 256 ) {
			String pad = "00".substring(temp.length() );
			return "\\x" + pad + temp.toUpperCase();
		}

		//Otherwise encode with \\uHHHH
		String pad = "0000".substring(temp.length() );
		return "\\u" + pad + temp.toUpperCase();
	}


	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * See http://www.planetpdf.com/codecuts/pdfs/tutorial/jsspec.pdf 
	 * Formats all are legal both upper/lower case:
	 *   \\a - special characters
	 *   \\xHH
	 *   \\uHHHH
	 *   \\OOO (1, 2, or 3 digits)
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
		if (first != '\\' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		if ( second == null ) {
			input.reset();
			return null;
		}

		// \0 collides with the octal decoder and is non-standard
		// if ( second.charValue() == '0' ) {
		//	return Character.valueOf( (char)0x00 );
		if (second == 'b' ) {
			return 0x08;
		} else if (second == 't' ) {
			return 0x09;
		} else if (second == 'n' ) {
			return 0x0a;
		} else if (second == 'v' ) {
			return 0x0b;
		} else if (second == 'f' ) {
			return 0x0c;
		} else if (second == 'r' ) {
			return 0x0d;
		} else if (second == '\"' ) {
			return 0x22;
		} else if (second == '\'' ) {
			return 0x27;
		} 
		else if (second == '\\' ) {
			return 0x5c;
		} 
		else if ( Character.toLowerCase( second.charValue() ) == 'x' )  //Look for \\xXX format
		{ 
			//Search for exactly 2 hex digits following
			StringBuilder sb = new StringBuilder();
			for ( int i=0; i<2; i++ ) {
				Character c = input.nextHex();
				if ( c != null ) sb.append( c );
				else {
					input.reset();
					return null;
				}
			}
			try {
				//Parse the hex digit and create a character
				int i = Integer.parseInt(sb.toString(), 16);
				if (Character.isValidCodePoint(i)) {
					return (char) i;
				}
			} catch( NumberFormatException e ) {
				input.reset();
				return null;
			}
		} 
		else if ( Character.toLowerCase( second.charValue() ) == 'u')  //Look for \\uXXXX format
		{
			//Search for exactly 4 hex digits following
			StringBuilder sb = new StringBuilder();
			for ( int i=0; i<4; i++ ) {
				Character c = input.nextHex();
				if ( c != null ) sb.append( c );
				else {
					input.reset();
					return null;
				}
			}
			try {
				//Parse the hex string and create a character
				int i = Integer.parseInt(sb.toString(), 16);
				if (Character.isValidCodePoint(i)) {
					return (char) i;
				}
			} catch( NumberFormatException e ) {
				//Throw an exception for malformed entity?
				input.reset();
				return null;
			}
		} 
		else if ( PushbackString.isOctalDigit(second) ) { //Look for one, two, or three octal digits
			StringBuilder sb = new StringBuilder();
			sb.append(second);

			Character c2 = input.next();
			if ( !PushbackString.isOctalDigit(c2) ) {
				input.pushback( c2 );
			} else {
				sb.append( c2 );
				Character c3 = input.next();
				if ( !PushbackString.isOctalDigit(c3) ) {
					input.pushback( c3 );
				} else {
					sb.append( c3 );
				}
			}

			try {
				//Parse the octal string and create a character
				int i = Integer.parseInt(sb.toString(), 8);
				if (Character.isValidCodePoint(i)) {
					return (char) i;
				}
			} catch( NumberFormatException e ) {
				input.reset();
				return null;
			}
		}

		//Ignore the backslash and return the character
		return second;
	}

}