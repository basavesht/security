package com.bosch.security.codecs;

/**
 * The pushback string is used by Codecs to allow them to push decoded characters back onto a string
 * for further decoding. This is necessary to detect double-encoding.
 */
public class PushbackString
{
	private String input;
	private Character pushback;
	private Character temp;
	private int index = 0;
	private int mark = 0;

	public PushbackString( String input ) {
		this.input = input;
	}

	public void pushback( Character c ) {
		pushback = c;
	}

	/**
	 * Get the current index of the PushbackString. Typically used in error messages.
	 * @return The current index of the PushbackString.
	 */
	public int index() {
		return index;
	}

	public boolean hasNext() {
		if ( pushback != null ) return true;
		if ( input == null ) return false;
		if ( input.length() == 0 ) return false;
		if ( index >= input.length() ) return false;
		return true;		
	}

	public Character next() {
		if ( pushback != null ) {
			Character save = pushback;
			pushback = null;
			return save;
		}
		if ( input == null ) return null;
		if ( input.length() == 0 ) return null;
		if ( index >= input.length() ) return null;		
		return Character.valueOf( input.charAt(index++) );
	}

	public Character nextHex() {
		Character c = next();
		if ( c == null ) return null;
		if ( isHexDigit( c ) ) return c;
		return null;
	}

	public Character nextOctal() {
		Character c = next();
		if ( c == null ) return null;
		if ( isOctalDigit( c ) ) return c;
		return null;
	}

	/**
	 * Returns true if the parameter character is a hexidecimal digit 0 through 9, a through f, or A through F.
	 * @param c
	 * @return
	 */
	public static boolean isHexDigit( Character c ) {
		if ( c == null ) return false;
		char ch = c.charValue();
		return (ch >= '0' && ch <= '9' ) || (ch >= 'a' && ch <= 'f' ) || (ch >= 'A' && ch <= 'F' );
	}

	/**
	 * Returns true if the parameter character is an octal digit 0 through 7.
	 * @param c
	 * @return
	 */
	public static boolean isOctalDigit( Character c ) {
		if ( c == null ) return false;
		char ch = c.charValue();
		return ch >= '0' && ch <= '7';
	}

	/**
	 * Return the next character without affecting the current index.
	 * @return
	 */
	public Character peek() {
		if ( pushback != null ) return pushback;
		if ( input == null ) return null;
		if ( input.length() == 0 ) return null;
		if ( index >= input.length() ) return null;		
		return Character.valueOf( input.charAt(index) );
	}

	/**
	 * Test to see if the next character is a particular value without affecting the current index.
	 * @param c
	 * @return
	 */
	public boolean peek( char c ) {
		if ( pushback != null && pushback.charValue() == c ) return true;
		if ( input == null ) return false;
		if ( input.length() == 0 ) return false;
		if ( index >= input.length() ) return false;		
		return input.charAt(index) == c;
	}	

	public void mark() {
		temp = pushback;
		mark = index;
	}

	public void reset() {
		pushback = temp;
		index = mark;
	}

	protected String remainder() {
		String output = input.substring( index );
		if ( pushback != null ) {
			output = pushback + output;
		}
		return output;
	}
}