package com.bosch.security.validator.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.bosch.security.codecs.Encoder;
import com.bosch.security.errors.ValidationException;
import com.bosch.security.util.NullSafe;
import com.bosch.security.util.StringUtilities;

/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 */
public class StringValidationRule extends BaseValidationRule
{

	protected List<Pattern> whitelistPatterns = new ArrayList<Pattern>();
	protected List<Pattern> blacklistPatterns = new ArrayList<Pattern>();
	protected int minLength = 0;
	protected int maxLength = Integer.MAX_VALUE;
	protected boolean validateInputAndCanonical = true;

	public StringValidationRule(String typeName) {
		super(typeName);
	}

	public StringValidationRule(String typeName, Encoder encoder ) {
		super(typeName, encoder);
	}

	public void addWhitelistPattern(String pattern) {
		if (pattern == null) {
			throw new IllegalArgumentException("Pattern cannot be null");
		}
		try {
			whitelistPatterns.add(Pattern.compile(pattern.trim(),Pattern.CASE_INSENSITIVE));
		} catch( PatternSyntaxException e ) {
			throw new IllegalArgumentException( "Validation misconfiguration, problem with specified pattern: " + pattern, e );
		}
	}

	public void addWhitelistPattern(Pattern p) {
		if (p == null) {
			throw new IllegalArgumentException("Pattern cannot be null");
		}
		whitelistPatterns.add( p );
	}

	public void addBlacklistPattern(String pattern) {
		if (pattern == null) {
			throw new IllegalArgumentException("Pattern cannot be null");
		}
		try {
			blacklistPatterns.add(Pattern.compile(pattern.trim(), Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL));
		} catch( PatternSyntaxException e ) {
			throw new IllegalArgumentException( "Validation misconfiguration, problem with specified pattern: " + pattern, e );
		}
	}

	public void addBlacklistPattern(Pattern p) {
		if (p == null) {
			throw new IllegalArgumentException("Pattern cannot be null");
		}
		blacklistPatterns.add( p );
	}

	public void setMinimumLength(int length) {
		minLength = length;
	}

	public void setMaximumLength(int length) {
		maxLength = length;
	}

	public void setValidateInputAndCanonical(boolean flag) {
		validateInputAndCanonical = flag;
	}


	@Override
	public String getValid(String context, String input) throws ValidationException
	{
		String data = null;

		//Check for empty/null
		if(checkEmpty(context, input) == null) {
			return null;
		}

		//Canonicalize and check
		if (validateInputAndCanonical) {
			checkLength(context, input);
			checkBlacklist(context, input);
			checkWhitelist(context, input);
			data = encoder.canonicalize( input );
		} 
		else { //Skip canonicalization
			data = input;			
		}

		//Check for empty/null
		if(checkEmpty(context, data, input) == null) {
			return null;
		}

		//Check against whitelisted and blacklisted patterns.
		checkLength(context, data, input);
		checkBlacklist(context, data, input);
		checkWhitelist(context, data, input);

		//Validation Passed.
		return data;
	}

	/**
	 * Checks input against whitelists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkWhitelist(String context, String input, String orig) throws ValidationException {
		for (Pattern p : whitelistPatterns) {
			if (!p.matcher(input).matches()) {
				throw new ValidationException(context + ": Invalid input. Please conform to regex " + p.pattern() + ( maxLength == Integer.MAX_VALUE ? "" : " with a maximum length of " + maxLength ), "Invalid input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input + (NullSafe.equals(orig,input) ? "" : ", orig=" + orig), context );
			}
		}

		return input;
	}

	/**
	 * Checks input against whitelists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkWhitelist(String context, String input) throws ValidationException {
		return checkWhitelist(context, input, input);
	}

	/**
	 * Checks input against blacklists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkBlacklist(String context, String input, String orig) throws ValidationException {
		for (Pattern p : blacklistPatterns) {
			if (p.matcher(input).find()) {
				throw new ValidationException( context + ": Invalid input. Dangerous input matching " + p.pattern() + " detected.", "Dangerous input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input + (NullSafe.equals(orig,input) ? "" : ", orig=" + orig), context );
			}
		}
		return input;
	}

	/**
	 * Checks input against blacklists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkBlacklist(String context, String input) throws ValidationException {
		return checkBlacklist(context, input, input);
	}

	/**
	 * checks input lengths
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkLength(String context, String input, String orig) throws ValidationException {
		if (input.length() < minLength) {
			throw new ValidationException( context + ": Invalid input. The minimum length of " + minLength + " characters was not met.", "Input does not meet the minimum length of " + minLength + " by " + (minLength - input.length()) + " characters: context=" + context + ", type=" + getTypeName() + "), input=" + input + (NullSafe.equals(input,orig) ? "" : ", orig=" + orig), context );
		}
		if (input.length() > maxLength) {
			throw new ValidationException( context + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (input.length()-maxLength) + " characters: context=" + context + ", type=" + getTypeName() + ", orig=" + orig +", input=" + input, context );
		}
		return input;
	}

	/**
	 * Checks input lengths
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkLength(String context, String input) throws ValidationException {
		return checkLength(context, input, input);
	}

	/**
	 * Checks input emptiness
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkEmpty(String context, String input, String orig) throws ValidationException {
		if(!StringUtilities.isEmpty(input))
			return input;
		if(allowNull)
			return null;
		throw new ValidationException( context + ": Input required.", "Input required: context=" + context + "), input=" + input + (NullSafe.equals(input,orig) ? "" : ", orig=" + orig), context );
	}

	/**
	 * Checks input emptiness
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkEmpty(String context, String input) throws ValidationException {
		return checkEmpty(context, input, input);
	}

}

