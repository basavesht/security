package com.bosch.security.codecs;

import java.io.IOException;

import com.bosch.security.errors.EncodingException;

public class EncodeDataUtils 
{

	//Utility class.
	private EncodeDataUtils () {

	}

	/**
	 * This method is equivalent to calling <pre>EncodeDataUtils.canonicalize(input, restrictMultiple, restrictMixed);</pre>
	 * The default values for restrictMultiple and restrictMixed come from security-config.properties
	 * <pre>
	 * Encoder.AllowMultipleEncoding=false
	 * Encoder.AllowMixedEncoding=false
	 * </pre>
	 * @param input the text to canonicalize
	 * @return a String containing the canonicalized text
	 */
	public static String canonicalize(final String input) {
		//TO-DO
		return null;
	}

	/**
	 * This method is the equivalent to calling <pre>Encoder.canonicalize(input, strict, strict);</pre>
	 * @param input the text to canonicalize
	 * @param strict true if checking for multiple and mixed encoding is desired, false otherwise
	 * @return a String containing the canonicalized text
	 */
	public static String canonicalize(final String input, boolean strict) {
		//TO-DO
		return null;
	}

	/**
	 * Canonicalization is simply the operation of reducing a possibly encoded
	 * string down to its simplest form. This is important, because attackers
	 * frequently use encoding to change their input in a way that will bypass
	 * validation filters, but still be interpreted properly by the target of
	 * the attack. Note that data encoded more than once is not something that a
	 * normal user would generate and should be regarded as an attack. 
	 * 
	 * The canonicalize method can
	 * be used to simplify just about any input down to its most basic form. Note that canonicalize doesn't
	 * handle Unicode issues, it focuses on higher level encoding and escaping schemes. In addition to simple
	 * decoding, canonicalize also handles:
	 * <ul><li>Perverse but legal variants of escaping schemes</li>
	 * <li>Multiple escaping </li>
	 * <li>Mixed escaping</li>
	 * <li>Nested escaping</li>
	 * </pre>
	 * 
	 * The default is "strict" mode that throws an IntrusionException if it receives anything not
	 * single-encoded with a single scheme. This is configurable
	 * in security-config.properties using the properties:
	 * <pre>
	 * Encoder.AllowMultipleEncoding=false
	 * Encoder.AllowMixedEncoding=false
	 * </pre>
	 * @param input the text to canonicalize
	 * @param restrictMultiple true if checking for multiple encoding is desired, false otherwise
	 * @param restrictMixed true if checking for mixed encoding is desired, false otherwise
	 *
	 * @return a String containing the canonicalized text
	 */
	public static String canonicalize(final String input, boolean restrictMultiple, boolean restrictMixed) {
		//TO-DO
		return null;
	}

	/**
	 * Encode data for use in HTML using HTML entity encoding
	 * @see <a href="http://en.wikipedia.org/wiki/Character_encodings_in_HTML">HTML Encodings [wikipedia.org]</a> 
	 * @param input the text to encode for HTML
	 * @return input encoded for HTML
	 */
	public static String encodeForHTML(final String input) {
		//TO-DO
		return null;
	}

	/**
	 * Decodes HTML entities.
	 * @param input the <code>String</code> to decode
	 * @return the newly decoded <code>String</code>
	 */
	public static String decodeForHTML(final String input) {
		//TO-DO
		return null;
	}

	/**
	 * Encode data for use in HTML attributes.
	 * @param input the text to encode for an HTML attribute
	 * @return input encoded for use as an HTML attribute
	 */
	public static String encodeForHTMLAttribute(final String input){ 
		//TO-DO
		return null;
	}

	/**
	 * Encode data for insertion inside a data value or function argument in JavaScript. Including user data 
	 * directly inside a script is quite dangerous. Great care must be taken to prevent including user data
	 * directly into script code itself, as no amount of encoding will prevent attacks there.
	 * @param input the text to encode for JavaScript
	 * @return input encoded for use in JavaScript
	 */
	public static String encodeForJavaScript(final String input) {
		//TO-DO
		return null;
	}


	/**
	 * Encode input for use in a SQL query, according to the selected codec 
	 * (appropriate codecs include the MySQLCodec and OracleCodec).
	 * 
	 * This method is not recommended. The use of the PreparedStatement 
	 * interface is the preferred approach. However, if for some reason 
	 * this is impossible, then this method is provided as a weaker 
	 * alternative. 
	 * 
	 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/guide/jdbc/getstart/statement.html">JDBC Specification</a>
	 * @param codec 
	 * 		a Codec that declares which database 'input' is being encoded for (ie. MySQL, Oracle, etc.)
	 * @param input 
	 * 		the text to encode for SQL
	 * 
	 * @return input encoded for use in SQL
	 */
	public static String encodeForSQL(Codec codec, final String input) {
		//TO-DO
		return null;
	}

	/**
	 * Encode data for use in an XPath query.
	 * @param input the text to encode for XPath
	 * @return input encoded for use in XPath
	 */
	public static String encodeForXPath(final String input) {
		//TO-DO
		return null;
	}

	/**
	 * Encode data for use in an XML element. The implementation should follow the <a
	 * href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
	 * Standard</a> from the W3C.
	 * <p>
	 * The use of a real XML parser is strongly encouraged. However, in the
	 * hopefully rare case that you need to make sure that data is safe for
	 * inclusion in an XML document and cannot use a parse, this method provides
	 * a safe mechanism to do so.
	 * @see <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding Standard</a>
	 * @param input the text to encode for XML
	 * @return input encoded for use in XML
	 */
	public static String encodeForXML(final String input) {
		//TO-DO
		return null;
	}

	/**
	 * Encode data for use in an XML attribute. The implementation should follow
	 * the <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
	 * Standard</a> from the W3C.
	 * <p>
	 * The use of a real XML parser is highly encouraged. However, in the
	 * hopefully rare case that you need to make sure that data is safe for
	 * inclusion in an XML document and cannot use a parse, this method provides
	 * a safe mechanism to do so.
	 * @see <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding Standard</a>
	 * @param input the text to encode for use as an XML attribute
	 * @return input encoded for use in an XML attribute
	 */
	public static String encodeForXMLAttribute(final String input) {
		//TO-DO
		return null;
	}

	/**
	 * Encode for use in a URL. This method performs <a
	 * href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding</a>
	 * on the entire string.
	 * @see <a href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding</a>
	 * @param input the text to encode for use in a URL
	 * @return input encoded for use in a URL
	 * @throws EncodingException if encoding fails
	 */
	public static String encodeForURL(final String input)  {
		//TO-DO
		return null;
	}

	/**
	 * Decode from URL. Implementations should first canonicalize and
	 * detect any double-encoding. If this check passes, then the data is decoded using URL
	 * decoding.
	 * @param input the text to decode from an encoded URL
	 * @return the decoded URL value
	 * @throws EncodingException 
	 * 		if decoding fails
	 */
	public static String decodeFromURL(final String input) {
		//TO-DO
		return null;
	}

	/**
	 * Encode for Base64.
	 * @param input the text to encode for Base64
	 * @param wrap the encoder will wrap lines every 64 characters of output
	 * @return input encoded for Base64
	 */
	public static String encodeForBase64(byte[] input, boolean wrap) {
		//TO-DO
		return null;
	}

	/**
	 * Decode data encoded with BASE-64 encoding.
	 * @param input the Base64 text to decode
	 * @return input decoded from Base64
	 * @throws IOException
	 */
	public static byte[] decodeFromBase64(final String input) throws IOException {
		//TO-DO
		return null;
	}
}
