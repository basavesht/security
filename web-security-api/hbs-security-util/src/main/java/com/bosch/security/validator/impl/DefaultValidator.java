package com.bosch.security.validator.impl;

import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.codecs.Encoder;
import com.bosch.security.errors.ValidationException;
import com.bosch.security.util.SecurityHandler;
import com.bosch.security.validator.Validator;
import com.bosch.security.validator.rules.DateValidationRule;
import com.bosch.security.validator.rules.StringValidationRule;

/**
 * Reference implementation of the Validator interface. This implementation
 * relies on the Encoder, Java Pattern (regex), Date,
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization.
 */
public class DefaultValidator implements Validator 
{ 
	private static volatile Validator instance = null;
	private static Logger logger = LoggerFactory.getLogger(DefaultValidator.class);

	public static Validator getInstance() {
		if ( instance == null ) {
			synchronized ( Validator.class ) {
				if ( instance == null ) {
					instance = new DefaultValidator();
				}
			}
		}
		return instance;
	}

	private Encoder encoder = null;

	/**
	 * Default constructor uses the ESAPI standard encoder for canonicalization.
	 */
	public DefaultValidator() {
		this.encoder = SecurityHandler.encoder();
	}

	/**
	 * Construct a new DefaultValidator that will use the specified
	 * Encoder for canonicalization.
	 * @param encoder
	 */
	public DefaultValidator(Encoder encoder ) {
		this.encoder = encoder;
	}

	@Override
	public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException 
	{
		try 
		{
			//Remove the tailing spaces..
			if(input != null) {
				input =  input.trim();
			}

			//Initialize a validation rule for the string inputs. 
			StringValidationRule stringValidationRuleSet = new StringValidationRule(type, encoder);

			//Fetch the white-listed pattern based on the type...
			Pattern p = SecurityHandler.securityConfiguration().getValidationPattern(type);
			if (p != null ) {
				stringValidationRuleSet.addWhitelistPattern(p);
			} else {
				throw new IllegalArgumentException("The selected type [" + type + "] was not set via the validation configuration");
			}

			//Fetch all the black-listed patterns (XSS etc) based on the type...
			List<Pattern> patterns = SecurityHandler.securityConfiguration().getXSSPatterns();
			if(patterns!=null && !patterns.isEmpty()) {
				for(Pattern pattern : patterns) {
					if (pattern != null ) {
						stringValidationRuleSet.addBlacklistPattern(pattern);
					}
				}
			}

			//Set other rules parameters
			stringValidationRuleSet.setMaximumLength(maxLength);
			stringValidationRuleSet.setAllowNull(allowNull);
			stringValidationRuleSet.setValidateInputAndCanonical(canonicalize);
			stringValidationRuleSet.getValid(context, input);
			return true;
		} 
		catch (ValidationException e) {
			logger.error("Validation Exception : {} + {} ", e.getMessage(), e.getLogMessage());
			return false;
		}
	}

	@Override
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException 
	{
		try 
		{
			//Remove the tailing spaces..
			if(input != null) {
				input =  input.trim();
			}

			//Initialize a validation rule for the string inputs. 
			StringValidationRule stringValidationRuleSet = new StringValidationRule(type, encoder);

			//Fetch the white-listed pattern based on the type...
			Pattern p = SecurityHandler.securityConfiguration().getValidationPattern(type);
			if (p != null ) {
				stringValidationRuleSet.addWhitelistPattern(p);
			} else {
				throw new IllegalArgumentException("The selected type [" + type + "] was not set via the validation configuration");
			}

			//Set other rules parameters
			stringValidationRuleSet.setMaximumLength(maxLength);
			stringValidationRuleSet.setAllowNull(allowNull);
			stringValidationRuleSet.setValidateInputAndCanonical(canonicalize);
			return stringValidationRuleSet.getValid(context, input);
		} 
		catch (ValidationException e) {
			throw e;
		}
	}

	@Override
	public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException 
	{
		try{
			// Initialize Date Validation Rule for the Date Inputs
			DateValidationRule dateValidationRuleSet = new DateValidationRule(encoder,format);

			//Set other rules parameters
			dateValidationRuleSet.setAllowNull(allowNull);
			dateValidationRuleSet.getValid(context, input);
			return true;
		}
		catch (ValidationException e) {
			logger.error("Validation Exception : {} + {} ", e.getMessage(), e.getLogMessage());
			return false;
		}
	}

	@Override
	public boolean isValidDirectoryPath(String context, String input, boolean allowNull) throws ValidationException 
	{
		try 
		{
			//Validate..
			if (input == null){
				if (allowNull) {
					return true ;
				}
				else  {
					throw new ValidationException("Invalid input : isValidDirectoryPath() input : {} " ,input);
				}
			}

			//Check dir exists 
			File dir = new File(input);
			if (!dir.exists()) {
				throw new ValidationException("Validation Exception : Invalid directory name context = {} and input ={} ", context, input );
			}
			if (!dir.isDirectory()) {
				throw new ValidationException("Validation Exception : Invalid directory name context = {} and input ={} ", context, input );
			}

			//Check canonical form matches input
			String canonicalPath = dir.getCanonicalPath();
			getValidInput(context, canonicalPath, "DirectoryName", 255, false, false);
			return true;
		} 
		catch (Exception e) {
			logger.error(context + ": Invalid directory name", "Failure to validate directory path: context=" + context + ", input=" + input, e, context );
			return false;
		}
	}

	@Override
	public boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws ValidationException
	{
		//Validate..
		if ((allowedExtensions == null) || (allowedExtensions.isEmpty())) {
			throw new ValidationException("Internal Error", "getValidFileName called with an empty or null list of allowed Extensions, therefore no files can be uploaded" );
		}

		//Detect path manipulation
		String canonical = "";
		try 
		{
			//Validate..
			if (input == null){
				if (allowNull) {
					return true ;
				}
				else  {
					throw new IllegalArgumentException("Invalid input : isValidFileName() input : " +input);
				}
			}

			// Validate file name 
			canonical = new File(input).getCanonicalFile().getName();
			getValidInput(context, input, "FileName", 255, true, false);

			File f = new File(canonical);
			String c = f.getCanonicalPath();
			String cpath = c.substring(c.lastIndexOf(File.separator) + 1);

			// The path is valid if the input matches the canonical path
			if (!input.equals(cpath)) {
				throw new ValidationException("Validation Exception : Invalid file name context = {} and input = {} ", context, input );
			}
		} 
		catch (IOException e) {
			throw new ValidationException("Validation Exception : Invalid file name context = {} and input = {} ", context, input );
		}

		// Verify extensions
		Iterator<String> i = allowedExtensions.iterator();
		while (i.hasNext()) {
			String ext = i.next();
			if (input.toLowerCase().endsWith(ext.toLowerCase())) {
				return true;
			}
		}
		throw new ValidationException( context + ": Invalid file name does not have valid extension ( "+allowedExtensions+")", "Invalid file name does not have valid extension ( "+allowedExtensions+"): context=" + context+", input=" + input, context );
	}

	@Override
	public boolean isValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull) throws ValidationException {
		//TO-DO
		return false;
	}

	@Override
	public boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException {
		//TO-DO
		return false;
	}
}
