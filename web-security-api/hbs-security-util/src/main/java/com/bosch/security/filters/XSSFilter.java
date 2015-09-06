package com.bosch.security.filters;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.errors.ValidationException;
import com.bosch.security.util.SecurityHandler;
import com.bosch.security.util.ValidationType;

public class XSSFilter 
{
	private static Logger logger = LoggerFactory.getLogger(XSSFilter.class);

	/**
	 * Utility method to check for the possible Cross Site Scripting attack.
	 * @param req - XSSRequestContainer contains request body, header and cookies if present.
	 * @return
	 */
	public static boolean isPossibleXSSAttack (XSSRequestContainer req) {
		try {
			logger.debug("Checking for the possible XSS Attack on the request parameters.");
			if(isHTTPParameterMapValid(req.getBody()) && isHTTPParameterMapValid(req.getQueryString()) && isHTTPHeaderMapValid(req.getHeaders())) {
				return false;
			}
			return true;
		} 
		catch (Exception e) {
			//already logged..
			return true;
		}
	}

	/**
	 * Check for all the XSS attack possible after canonicalizing the HTTP parameters.
	 * @param Map containing the request headers
	 * @return A boolean flag defining a possible XSS attack.
	 */
	@SuppressWarnings("rawtypes")
	public static boolean isHTTPParameterMapValid(Map<String,String[]> requestParams) 
	{
		//Incase the map is empty, just return true.
		if(requestParams == null || requestParams.isEmpty()) {
			return true;
		}

		for (Object o : requestParams.entrySet()) {
			try {
				Map.Entry e = (Map.Entry) o;
				String httpParamName = (String) e.getKey();
				boolean isValidHttpParamName = SecurityHandler.validator().isValidInput("HTTP parameter name: ", httpParamName, ValidationType.HTTP_PARAMETERNAME.getType(), Integer.MAX_VALUE, false, true);
				if(!isValidHttpParamName) {
					return isValidHttpParamName;
				}

				String[] value = (String[]) e.getValue();
				for (int j = 0; j < value.length; j++) {
					boolean isValidHttpParamValue  = SecurityHandler.validator().isValidInput("HTTP parameter value: ", value[j], ValidationType.HTTP_PARAMETERVALUE.getType(), Integer.MAX_VALUE, true, true);
					if(!isValidHttpParamValue) {
						return isValidHttpParamValue;
					}
				}
			} catch (ValidationException e) {
				//already logged..
			}
		}
		return true;
	}

	/**
	 * Check for all the XSS attack possible after canonicalizing the HTTP headers.
	 * @param Map containing the request headers
	 * @return A boolean flag defining a possible XSS attack.
	 */
	@SuppressWarnings("rawtypes")
	public static boolean isHTTPHeaderMapValid(Map<String,String[]> requestHeaders) 
	{
		//Incase the map is empty, just return true.
		if(requestHeaders == null || requestHeaders.isEmpty()) {
			return true;
		}

		for (Object o : requestHeaders.entrySet()) 
		{
			try
			{
				Map.Entry e = (Map.Entry) o;
				String httpHeaderName = (String) e.getKey();

				// Reject if the input contains non-printable ascii characters in http header name. 
				if (httpHeaderName!=null  && !httpHeaderName.matches("\\p{Print}*")) {
					logger.error("Bad request : Contain non printable ascii characters in header name");
					return false; 
				}

				// Validate the input for the black/white listing approach. 
				boolean isValidHttpParamName = SecurityHandler.validator().isValidInput("HTTP header name: ", httpHeaderName, ValidationType.HTTP_HEADERNAME.getType(), Integer.MAX_VALUE, false, true);
				if(!isValidHttpParamName) {
					return isValidHttpParamName;
				}

				String[] value = (String[]) e.getValue();
				for (int j = 0; j < value.length; j++) {

					// Reject if the input contains non-printable ascii characters in http header value. 
					if (value[j]!=null  && !value[j].matches("\\p{Print}*")) {
						logger.error("Bad request : Contain non printable ascii characters in header value");
						return false; 
					}

					// Validate the input for the black/white listing approach. 
					boolean isValidHttpParamValue  = SecurityHandler.validator().isValidInput("HTTP header value: ", value[j], ValidationType.HTTP_HEADERVALUE.getType(), Integer.MAX_VALUE, true, true);
					if(!isValidHttpParamValue) {
						return isValidHttpParamValue;
					}
				}
			} catch (ValidationException e) {
				//already logged..
			}
		}
		return true;
	}
}
