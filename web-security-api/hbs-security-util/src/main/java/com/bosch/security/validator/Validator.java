package com.bosch.security.validator;

import java.io.File;
import java.text.DateFormat;
import java.util.List;

import com.bosch.security.errors.ValidationException;


/**
 * The Validator interface defines a set of methods for canonicalizing and
 * validating untrusted input. Implementors should feel free to extend this
 * interface to accommodate their own data formats. Rather than throw exceptions,
 * this interface returns boolean results because not all validation problems
 * are security issues. Boolean returns allow developers to handle both valid
 * and invalid results more cleanly than exceptions.
 * <P>
 * Implementations must adopt a "whitelist" approach to validation where a
 * specific pattern or character set is matched. "Blacklist" approaches that
 * attempt to identify the invalid or disallowed characters are much more likely
 * to allow a bypass with encoding or other tricks.
 */
public interface Validator {

	/**
	 * Returns validated input as a String with optional canonicalization. Invalid input will generate a descriptive ValidationException,
	 * and input that is clearly an attack will generate a descriptive IntrusionException.
	 * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name that maps to the actual regular expression from "security-config.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param canonicalize  If canonicalize is true then input will be canonicalized before validation
	 * @return The canonicalized user input.
	 * @throws ValidationException
	 */
	public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException;

	/**
	 * Returns true if the Date is valid . Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input  The actual user input data to validate.
	 * @param format Required formatting of date inputted.
	 * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return A valid date as a Date
	 * @throws ValidationException
	 */
	public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException;

	/**
	 * Returns a canonicalized and validated directory path as a String, provided that the input
	 * maps to an existing directory that is an existing subdirectory (at any level) of the specified parent. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input The actual input data to validate.
	 * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return A valid directory path
	 * @throws ValidationException
	 */
	public boolean isValidDirectoryPath(String context, String input, boolean allowNull) throws ValidationException;


	/**
	 * Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in "ESAPI.properties". Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input The actual input data to validate.
	 * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return A valid file name
	 * @throws ValidationException
	 */
	public boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws ValidationException;

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param filepath The file path of the uploaded file.
	 * @param filename The filename of the uploaded file
	 * @param content A byte array containing the content of the uploaded file.
	 * @param maxBytes The max number of bytes allowed for a legal file upload.
	 * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @throws ValidationException
	 */
	public boolean isValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull) throws ValidationException;

	/**
	 * Returns a validated integer. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * @param context A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input The actual input data to validate.
	 * @param allowNull If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param minValue Lowest legal value for input.
	 * @param maxValue Highest legal value for input.
	 * @return A validated number as an integer.
	 * @throws ValidationException
	 */
	public boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException;

	/**
	 * Return validated canocnialzed code,,,
	 * @param context
	 * @param input
	 * @param type
	 * @param maxLength
	 * @param allowNull
	 * @param canonicalize
	 * @return
	 * @throws ValidationException
	 */
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException;
}

