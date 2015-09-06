package com.bosch.encrypt.db;

import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Properties;
import java.util.Scanner;

/**
 * Encryption Utility - This utility is to provide capability to the user to encyrpt sensitive information like passwords using 
   JASYPT Utility api. The output needs to be then copied to the corresponding property file. 
   Currently this utility is used to encrypt database passwords.
 * @author TEB1PAL
 *
 */
public final class EncryptDBCredentials
{
	private static final String RESOURCE_FILE = "encrypt-config.properties";
	private static final String resourceDirectory = "config"; //Default resource directory path if not specified..
	private static Properties result = null;

	public static void main(String[] args) 
	{
		Scanner console = null;
		try 
		{
			//Creating Scanner instance to scan console for User input
			console = new Scanner(System.in);

			System.out.println("Please enter the password (case-sensitive) to be encrypted : ");
			String password = null;
			if(console.hasNextLine()) {
				password = console.next();
			}

			System.out.println("Utility uses Password Based Encrytpion (PBE) mechanism for the encryption");
			System.out.println("Please enter the master password (case-sensitive) required for PBE algorithm : ");
			String masterPassword = null;
			if(console.hasNextLine()) {
				masterPassword = console.next();
			}

			//Validate 
			if(password == null || masterPassword == null) {
				throw new IllegalAccessException("Could not read the input parameters for System.in");	
			}

			EncryptDBCredentials encrypt = new EncryptDBCredentials();
			encrypt.loadConfigurationFromClasspath();
			encrypt.invokeJasyptMain (password, masterPassword);
			System.out.println("\r\n" + "Encryption successfull. Please copy the "
					+ "encrypted value in the corresponding property file. \r\n"
					+ "Remember to enclose the encrypted password with ENC().");

		} 
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			console.close();
		}
	}

	/**
	 * Invokes the Jasypt utiltity to encrypt passwords. 
	 * @param password
	 */
	@SuppressWarnings("rawtypes")
	private void invokeJasyptMain(String password, String masterPassword) 
	{
		try 
		{
			Class<?> c = Class.forName("org.jasypt.intf.cli.JasyptPBEStringEncryptionCLI");
			Class[] argTypes = new Class[] { String[].class };
			Method main = c.getDeclaredMethod("main", argTypes);

			String args[] = new String[getNumberOfArguments()];
			args[0] = "input=" + password; //Database Passoword
			args[1] = "password=" + masterPassword; //Master Key Password
			args[2] = "algorithm=" + result.getProperty("Encryptor.PBEEncryptionAlgorithm");
			if(result.getProperty("Encryptor.PreferredJCEProvider")!=null 
					&& !result.getProperty("Encryptor.PreferredJCEProvider").isEmpty()) {
				args[3] = "providerClassName=" + result.getProperty("Encryptor.PreferredJCEProvider");
			}

			main.invoke(null, (Object)args);
		} 
		catch (ClassNotFoundException x) {
			x.printStackTrace();
		} 
		catch (NoSuchMethodException x) {
			x.printStackTrace();
		} 
		catch (IllegalAccessException x) {
			x.printStackTrace();
		} 
		catch (InvocationTargetException x) {
			x.printStackTrace();
		}
	}

	/**
	 * Used to load Security.properties from a variety of different classpath locations.
	 * @param fileName The properties file filename.
	 * @throws Exception 
	 */
	private void loadConfigurationFromClasspath() throws Exception 
	{

		InputStream in = null;

		ClassLoader[] loaders = new ClassLoader[] {
				Thread.currentThread().getContextClassLoader(),
				ClassLoader.getSystemClassLoader(),
				getClass().getClassLoader() 
		};
		String[] classLoaderNames = {
				"current thread context class loader",
				"system class loader",
				"class loader for DefaultSecurityConfiguration class"
		};

		ClassLoader currentLoader = null;
		for (int i = 0; i < loaders.length; i++) {
			if (loaders[i] != null) 
			{
				currentLoader = loaders[i];
				try
				{
					//Root
					String currentClasspathSearchLocation = "/ (root)";
					in = loaders[i].getResourceAsStream(RESOURCE_FILE);

					//Resource Directory 
					if (in == null) {
						currentClasspathSearchLocation = resourceDirectory + "/";
						in = currentLoader.getResourceAsStream(resourceDirectory + "/" + RESOURCE_FILE);
					}

					//Resources 
					if (in == null) {
						currentClasspathSearchLocation = "resources/";
						in = currentLoader.getResourceAsStream("resources/" + RESOURCE_FILE);
					}

					//Load the properties
					if (in != null) {
						result = new Properties();
						result.load(in); // Can throw IOException
						System.out.println("SUCCESSFULLY LOADED " + RESOURCE_FILE + " via the CLASSPATH from '" +
								currentClasspathSearchLocation + "' using " + classLoaderNames[i] + "!");
						break;
					}
				} 
				catch (Exception e) {
					result = null;

				} 
				finally {
					try {
						in.close();
					} 
					catch (Exception e) {
					}
				}
			}
		}
		if (result == null) {
			throw new Exception("Failed to load " + RESOURCE_FILE + " as a classloader resource.");
		}
	}

	/**
	 * Gets the number of arguments passed to the JASYPT api..
	 * @return
	 */
	private int getNumberOfArguments () {
		if(result.getProperty("Encryptor.PreferredJCEProvider")!=null 
				&& !result.getProperty("Encryptor.PreferredJCEProvider").isEmpty()) {
			return 4;
		}
		else return 3;
	}

}
