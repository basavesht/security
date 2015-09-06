package com.bosch.security.codecs;

import java.util.Map;
import java.util.Set;

import com.bosch.security.util.CollectionsUtil;

/**
 * Implementation of the Codec interface for XML entity encoding.
 * This differes from HTML entity encoding in that only the following
 * named entities are predefined:
 * <ul>
 * 	<li>lt</li>
 * 	<li>gt</li>
 * 	<li>amp</li>
 * 	<li>apos</li>
 * 	<li>quot</li>
 * </ul>
 * However, the XML Specification 1.0 states in section 4.6 "Predefined
 * Entities" that these should still be declared for interoperability
 * purposes. As such, encoding in this class will not use them.
 *
 * It's also worth noting that unlike the HTMLEntityCodec, a trailing
 * semicolon is required and all valid codepoints are accepted.
 *
 * Note that it is a REALLY bad idea to use this for decoding as an XML
 * document can declare arbitrary entities that this Codec has no way
 * of knowing about. Decoding is included for completeness but it's use
 * is not recommended. Use a XML parser instead!
 */
public class XMLEntityCodec extends Codec
{
	private static final String ALPHA_NUMERIC_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static final String UNENCODED_STR = ALPHA_NUMERIC_STR + " \t";
	private static final Set<Character> UNENCODED_SET = CollectionsUtil.strToUnmodifiableSet(UNENCODED_STR);
	private static final HashTrie<Character> entityToCharacterMap;

	static
	{
		entityToCharacterMap = new HashTrie<Character>();
		entityToCharacterMap.put("lt", '<');
		entityToCharacterMap.put("gt", '>');
		entityToCharacterMap.put("amp", '&');
		entityToCharacterMap.put("apos", '\'');
		entityToCharacterMap.put("quot", '"');
	}

	/**
	 * Encodes a Character using XML entities as necessary.
	 * @param immune characters that should not be encoded as entities
	 */
	@Override
	public String encodeCharacter(char[] immune, Character c)
	{
		//Check for immune characters
		if(containsCharacter(c, immune))
			return c.toString();

		//Check for unencoded characters
		if(UNENCODED_SET.contains(c))
			return c.toString();

		return "&#x" + Integer.toHexString(c.charValue()) + ";";
	}

	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * Legal formats:
	 * <ul>
	 * 	<li>&amp;#dddd;</li>
	 * 	<li>&amp;#xhhhh;</li>
	 * 	<li>&amp;name;</li>
	 * </ul>
	 */
	@Override
	public Character decodeCharacter(PushbackString input)
	{
		Character ret = null;
		Character first;
		Character second;

		input.mark();
		try
		{
			first = input.next();
			if(first == null)
				return null;

			//If this is not an encoded character, return null
			if(first != '&')
				return null;

			//Test for numeric encodings
			second = input.next();
			if(second==null)
				return null;

			if(second=='#') {	//Handle numbers
				ret = getNumericEntity(input);
			}
			else if(Character.isLetter(second.charValue())) {	//Handle entities
				input.pushback(second);
				ret = getNamedEntity(input);
			}
		}
		finally {
			if(ret == null)
				input.reset();
		}
		return ret;
	}

	/**
	 * Converts the rest of a numeric entity to a character.
	 * @param input The input to read from. It is assumed that input
	 * 	is positioned at the character after the &amp;#
	 * @return The character decoded or null on failure.
	 */
	private static Character getNumericEntity(PushbackString input)
	{
		Character first = input.peek();

		if(first == null)
			return null;

		if(first=='x'||first=='X') {
			input.next();	//Nuke X
			return parseHex(input);
		}
		return parseNumber(input);
	}

	/**
	 * Convert a integer code point to a Character.
	 * @param i the integer
	 * @return i as a Character or null if i is a invalid code point
	 * 	or outside of the Java char range.
	 */
	private static Character int2char(int i)
	{
		if(!Character.isValidCodePoint(i))
			return null;
		if(!(Character.MIN_VALUE <= i && i <= Character.MAX_VALUE))
			return null;	// we can't 0x010000-0x100000 currently
		return (char)i;
	}

	/**
	 * Converts the rest of a decimal numeric entity to a character.
	 * @param input The input to read from. It is assumed that input
	 * 	is positioned at the character after the &amp;# and that
	 *	the next char is not a 'x' or 'X'.
	 * @return The character decoded or null on failutre.
	 */
	private static Character parseNumber(PushbackString input)
	{
		StringBuilder sb = new StringBuilder();
		Character c;
		while((c=input.next())!=null)
		{
			// end of entity?
			if(c==';')
				break;

			// check for digit
			if(!Character.isDigit(c.charValue()))
				return null;
			sb.append(c);
		}
		if(c==null)
			return null;	// not ';' termintated
		if(sb.length()<=0)	// no digits
			return null;
		try
		{
			return int2char(Integer.parseInt(sb.toString()));
		}
		catch(NumberFormatException e)
		{
			return null;
		}
	}

	/**
	 * Converts the rest of a hexidecimal numeric entity to a character.
	 * @param input The input to read from. It is assumed that input
	 * 	is positioned at the character after the &amp;#[xX]
	 * @return The character decoded or null on failutre.
	 */
	private static Character parseHex(PushbackString input)
	{
		Character c;
		StringBuilder sb = new StringBuilder();
		input_loop: while((c=input.next())!=null)
		{
			switch(c.charValue())
			{
			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				sb.append(c);
				break;
			case ';':
				break input_loop;
			default:
				return null;
			}
		}
		if(c==null)
			return null;	// not ';' termintated
		if(sb.length()<=0)	// no digits
			return null;
		try
		{
			return int2char(Integer.parseInt(sb.toString(),16));
		}
		catch(NumberFormatException e)
		{
			return null;
		}
	}

	/**
	 * 
	 * Converts the rest of a named entity to a character.
	 * null if no decoding is possible.
	 * @param input The input to read from. It is assumed that input
	 * 	is positioned at the character after the &amp;.
	 * @return The character decoded or null on failutre.
	 */
	private Character getNamedEntity(PushbackString input)
	{
		StringBuilder possible = new StringBuilder();
		Map.Entry<CharSequence,Character> entry;
		int len;

		//Kludge around PushbackString....
		len = Math.min(input.remainder().length(), entityToCharacterMap.getMaxKeyLength()+1);
		for(int i=0;i<len;i++)
			possible.append(Character.toLowerCase(input.next()));

		//Look up the longest match
		entry = entityToCharacterMap.getLongestMatch(possible);
		if(entry == null)
			return null;	//No match, caller will reset input
		len = entry.getKey().length();	
		if(possible.length() <= len || possible.charAt(len)!=';')
			return null;	//Not semicolon

		//Fixup input
		input.reset();
		input.next();	//Read &
		for(int i=0;i<len;i++)
			input.next();
		input.next();	//Read semicolen
		return entry.getValue();
	}
}
