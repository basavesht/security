package com.bosch.security.codecs.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.codecs.Codec;
import com.bosch.security.codecs.Encoder;
import com.bosch.security.codecs.HTMLEntityCodec;
import com.bosch.security.codecs.JavaScriptCodec;
import com.bosch.security.codecs.PercentCodec;
import com.bosch.security.codecs.XMLEntityCodec;
import com.bosch.security.errors.EncodingException;
import com.bosch.security.errors.IntrusionException;
import com.bosch.security.logger.EventType;
import com.bosch.security.util.SecurityHandler;

/**
 * Reference implementation of the Encoder interface. This implementation takes
 * a whitelist approach to encoding, meaning that everything not specifically identified in a
 * list of "immune" characters is encoded.
 */
public class DefaultEncoder implements Encoder 
{
	private static volatile Encoder singletonInstance;

	public static Encoder getInstance() {
		if ( singletonInstance == null ) {
			synchronized ( DefaultEncoder.class ) {
				if ( singletonInstance == null ) {
					singletonInstance = new DefaultEncoder();
				}
			}
		}
		return singletonInstance;
	}

	//Codecs
	private List<Codec> codecs = new ArrayList<Codec>();
	private HTMLEntityCodec htmlCodec = new HTMLEntityCodec();
	private XMLEntityCodec xmlCodec = new XMLEntityCodec();
	private JavaScriptCodec javaScriptCodec = new JavaScriptCodec();
	private PercentCodec percentCodec = new PercentCodec();

	private final Logger logger = LoggerFactory.getLogger(DefaultEncoder.class);

	/**
	 * Character sets that define characters (in addition to alphanumerics) that are
	 * immune from encoding in various formats
	 */
	private final static char[] IMMUNE_HTML = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_HTMLATTR = { ',', '.', '-', '_' };
	private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '_' };
	private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_SQL = { ' ' };
	private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };
	private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };

	/**
	 * Instantiates a new DefaultEncoder
	 */
	private DefaultEncoder() {
		codecs.add(htmlCodec);
		codecs.add(percentCodec);
	}

	@Override
	public String canonicalize(String input ) {
		if ( input == null ) {
			return null;
		}
		return canonicalize(input, 
				!SecurityHandler.securityConfiguration().getAllowMultipleEncoding(),
				!SecurityHandler.securityConfiguration().getAllowMixedEncoding() );
	}

	@Override
	public String canonicalize(String input, boolean strict) {
		return canonicalize(input, strict, strict);
	}

	@Override
	public String canonicalize(String input, boolean restrictMultiple, boolean restrictMixed) 
	{
		if ( input == null ) {
			return null;
		}

		String working = input;
		Codec codecFound = null;
		int mixedCount = 1;
		int foundCount = 0;
		boolean clean = false;

		while(!clean) 
		{
			clean = true;

			//Try each codec and keep track of which ones work
			Iterator<Codec> i = codecs.iterator();
			while (i.hasNext()) {
				Codec codec = (Codec)i.next();
				String old = working;
				working = codec.decode(working);
				if ( !old.equals(working) ) {
					if (codecFound != null && codecFound != codec) {
						mixedCount++;
					}
					codecFound = codec;
					if (clean) {
						foundCount++;
					}
					clean = false;
				}
			}
		}

		//Do strict tests and handle if any mixed, multiple, nested encoding were found
		if (foundCount >= 2 && mixedCount > 1 ) {
			if ( restrictMultiple || restrictMixed ) {
				throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
			} else {
				logger.debug(EventType.SECURITY_FAILURE.getEvent() + " {}", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
			}
		}
		else if ( foundCount >= 2 ) {
			if ( restrictMultiple ) {
				throw new IntrusionException( "Input validation failure" , "Multiple ("+ foundCount +"x) encoding detected in " + input );
			} else {
				logger.debug(EventType.SECURITY_FAILURE.getEvent() + " {}", "Multiple ("+ foundCount +"x) encoding detected in " + input );
			}
		}
		else if ( mixedCount > 1 ) {
			if ( restrictMixed ) {
				throw new IntrusionException( "Input validation failure", "Mixed encoding ("+ mixedCount +"x) detected in " + input );
			} else {
				logger.debug(EventType.SECURITY_FAILURE.getEvent() + " {}", "Mixed encoding ("+ mixedCount +"x) detected in " + input );
			}
		}
		return working;
	}

	@Override
	public String encodeForHTML(String input) {
		if( input == null ) {
			return null;
		}
		return htmlCodec.encode( IMMUNE_HTML, input);	    
	}

	@Override
	public String decodeForHTML(String input) {

		if( input == null ) {
			return null;
		}
		return htmlCodec.decode( input);	 
	}

	@Override
	public String encodeForHTMLAttribute(String input) {
		if( input == null ) {
			return null;
		}
		return htmlCodec.encode( IMMUNE_HTMLATTR, input);
	}

	@Override
	public String encodeForJavaScript(String input) {
		if( input == null ) {
			return null;
		}
		return javaScriptCodec.encode(IMMUNE_JAVASCRIPT, input);
	}

	@Override
	public String encodeForSQL(Codec codec, String input) {
		if( input == null ) {
			return null;
		}
		return codec.encode(IMMUNE_SQL, input);
	}

	@Override
	public String encodeForXPath(String input) {
		if( input == null ) {
			return null;	
		}
		return htmlCodec.encode( IMMUNE_XPATH, input);
	}

	@Override
	public String encodeForXML(String input) {
		if( input == null ) {
			return null;	
		}
		return xmlCodec.encode( IMMUNE_XML, input);
	}

	@Override
	public String encodeForXMLAttribute(String input) {
		if( input == null ) {
			return null;	
		}
		return xmlCodec.encode( IMMUNE_XMLATTR, input);
	}

	@Override
	public String encodeForURL(String input) throws EncodingException {
		if ( input == null ) {
			return null;
		}
		try {
			return URLEncoder.encode(input, SecurityHandler.securityConfiguration().getCharacterEncoding());
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Encoding failure", "Character encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Encoding failure", "Problem URL encoding input", e);
		}
	}

	@Override
	public String decodeFromURL(String input) throws EncodingException {
		if ( input == null ) {
			return null;
		}
		String canonical = canonicalize(input);
		try {
			return URLDecoder.decode(canonical, SecurityHandler.securityConfiguration().getCharacterEncoding());
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Decoding failed", "Character encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Decoding failed", "Problem URL decoding input", e);
		}
	}

	@Override
	public String encodeForBase64(byte[] input, boolean wrap) {
		if ( input == null ) {
			return null;
		}
		return Base64.encodeBase64String(input);
	}

	@Override
	public byte[] decodeFromBase64(String input) throws IOException {
		if ( input == null ) {
			return null;
		}
		return Base64.decodeBase64(input);
	}
}
