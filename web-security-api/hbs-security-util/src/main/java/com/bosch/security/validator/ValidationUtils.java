package com.bosch.security.validator;

import java.text.DateFormat;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.errors.ValidationException;
import com.bosch.security.util.SecurityHandler;
import com.bosch.security.util.ValidationType;

public class ValidationUtils {

	private static Logger logger = LoggerFactory.getLogger(ValidationUtils.class);
	private ValidationUtils() {

	}

	/**
	 * Validates the SSN
	 * @param ssn
	 * @return
	 */
	public static boolean isValidSSN (final String ssn) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", ssn, ValidationType.SSN.getType(), 11, false,false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.SSN) : {}", e);
			return false ;
		}
	}

	/**
	 * Validates the SSN after canonicalization
	 * @param ssn
	 * @return
	 */
	public static boolean isValidSSN (final String ssn, boolean isCanonicalize) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", ssn, ValidationType.SSN.getType(), 11, false, isCanonicalize);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.SSN) : {}", e);
			return false ;
		}
	}

	/**
	 * Validates the URL
	 * @param ssn
	 * @return
	 */
	public static boolean isValidURL (final String url) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", url, ValidationType.URL.getType(), Integer.MAX_VALUE, false, false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.URL) : {}", e);
			return false ;
		}	
	}

	/**
	 * Validates the URL after canonicalization
	 * @param ssn
	 * @return
	 */
	public static boolean isValidURL (final String url, boolean isCanonicalize) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", url, ValidationType.URL.getType(), Integer.MAX_VALUE, false, isCanonicalize);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.URL) : {}", e);
			return false ;
		}		
	}

	/**
	 * Validates the email
	 * @param ssn
	 * @return
	 */
	public static boolean isValidEmail (final String email) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", email, ValidationType.EMAIL.getType(), 100, false, false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.EMAIL) : {}", e);
			return false ;
		}	
	}

	/**
	 * Validates the IP Address
	 * @param ssn
	 * @return
	 */
	public static boolean isValidIPAddress (final String ip) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", ip, ValidationType.IP_ADDRESS.getType(), 20, false, false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.IP_ADDRESS) : {} ", e);
			return false ;
		}	
	}

	/**
	 * Validates the HTTP Param
	 * @param ssn
	 * @return
	 */
	public static boolean isValidHTTPParam (String httpParam) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", httpParam, ValidationType.HTTP_PARAMETERVALUE.getType(), Integer.MAX_VALUE, false, false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.HTTP_PARAMETER) : {}", e);
			return false ;
		}	
	}

	/**
	 * Validates the HTTP Parameter value after canonicalization
	 * @param ssn
	 * @return
	 */
	public static boolean isValidHTTPParam (String httpParam, boolean isCanonicalize) {
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidInput("InputParams", httpParam, ValidationType.HTTP_PARAMETERVALUE.getType(), Integer.MAX_VALUE, false, isCanonicalize);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.HTTP_PARAMETER) : {}", e);
			return false ;
		}	
	}

	/**
	 * Validates the Date format
	 * @param ssn
	 * @return
	 */
	public static boolean isValidDate (String date, DateFormat dt){
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidDate("Date", date, dt, false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.Date) : {}", e);
			return false ;
		}
	}

	/**
	 * Validates the Directory
	 * @param ssn
	 * @return
	 */
	public static boolean isValidDirectoryPath (String directoryPath){
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidDirectoryPath("Directory", directoryPath, false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.Directory) : {}", e);
			return false ;
		}
	}

	/**
	 * Validates the File Name
	 * @param ssn
	 * @return
	 */
	public static boolean isValidFileName (String fileName, List<String> allowedExtensions){
		Validator instance = SecurityHandler.validator();
		try {
			return instance.isValidFileName("FileName", fileName, allowedExtensions, false);
		} catch (ValidationException e) {
			logger.error("Input Validation failed (ValidationType.FileName) : {}", e);
			return false ;
		}
	}
}