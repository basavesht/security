package com.bosch.security.validator.rules;

import com.bosch.security.codecs.Encoder;
import com.bosch.security.errors.ValidationException;


public interface ValidationRule 
{
	/**
	 * Parse the input, throw exceptions if validation fails
	 * @param context for logging
	 * @param input the value to be parsed
	 * @return a validated value
	 * @throws ValidationException if any validation rules fail
	 */
	public Object getValid(String context, String input) throws ValidationException;

	/**
	 * Whether or not a valid valid can be null. getValid will throw an
	 * Exception and getSafe will return the default value if flag is set to true
	 * @param flag whether or not null values are valid/safe
	 */
	public void setAllowNull(boolean flag);

	/**
	 * Set the Validator type name for programmatically loading the validator.
	 * @param typeName
	 */
	public void setTypeName(String typeName);

	/**
	 * Set the encoder to use
	 * @param encoder
	 */
	public void setEncoder(Encoder encoder);

}