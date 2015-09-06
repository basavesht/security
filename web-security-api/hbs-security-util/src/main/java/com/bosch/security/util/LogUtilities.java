package com.bosch.security.util;

/**
 * Utility class to manage log files. 
 * @author teb1pal
 *
 */
public class LogUtilities 
{
	private LogUtilities(){

	}

	/**
	 * Ensure no CRLF injection into logs for forging records
	 * @param message
	 */
	public static void cleanLogRecords (String message) {
		String clean = message.replace('\n', '_').replace('\r', '_');
		if (SecurityHandler.securityConfiguration().getLogEncodingRequired()) {
			clean = SecurityHandler.encoder().encodeForHTML(message);
			if (!message.equals(clean)) {
				clean += " (Encoded)";
			}
		}
	}
}
