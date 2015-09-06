package com.bosch.security.util;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import com.bosch.security.errors.ConfigurationException;

/**
 * A generic object factory to create an object of class T. T must be a concrete
 * class that has a no-argument public constructor or a implementor of the Singleton pattern
 * that has a no-arg static getInstance method. If the class being created has a getInstance
 * method, it will be used as a singleton and newInstance() will never be called on the
 * class no matter how many times it comes through this factory.
 */
public class ObjFactory 
{
	/**
	 * Create an object based on the <code>className</code> parameter.
	 * 
	 * @param className	The name of the class to construct. Should be a fully qualified name and
	 * 					generally the same as type <code>T</code>
	 * @param typeName	A type name used in error messages / exceptions.
	 * @return	An object of type <code>className</code>, which is cast to type <code>T</code>.
	 * @throws	ConfigurationException thrown if class name not found in class path, or does not
	 * 			have a public, no-argument constructor, or is not a concrete class, or if it is
	 * 			not a sub-type of <code>T</code> (or <code>T</code> itself). Usually this is
	 * 			caused by a misconfiguration of the class names specified in the ESAPI.properties
	 * 			file. Also thrown if the CTOR of the specified <code>className</code> throws
	 * 			an <code>Exception</code> of some type.
	 */
	@SuppressWarnings({ "unchecked" })
	public static <T> T getInstance(String className, String typeName) throws ConfigurationException 
	{
		Object obj = null;
		String errMsg = null;
		try 
		{
			if (null == className || "".equals(className) ) {
				throw new IllegalArgumentException("Classname cannot be null or empty.");
			}
			if (null == typeName || "".equals(typeName) ) {
				typeName = "[unknown?]";
			}

			Class<?> theClass = Class.forName(className);

			try 
			{
				Method singleton = theClass.getMethod( "getInstance" );

				// If the implementation class contains a getInstance method that is not static throw exception
				if ( !Modifier.isStatic( singleton.getModifiers() ) ){
					throw new ConfigurationException( "Class [" + className + "] contains a non-static getInstance method." );
				}
				obj = singleton.invoke( null );
			} 
			catch (NoSuchMethodException e) {
				obj = theClass.newInstance();
			} 
			catch (SecurityException e) {
				throw new ConfigurationException( "The SecurityManager has restricted the object factory from getting a reference to the singleton implementation" +
						"of the class [" + className + "]", e );
			}

			return (T)obj;
		} 
		catch( IllegalArgumentException ex ) {
			errMsg = ex.toString() + " " + typeName + " type name cannot be null or empty.";
			throw new ConfigurationException(errMsg, ex);
		}
		catch ( ClassNotFoundException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be in class path.";
			throw new ConfigurationException(errMsg, ex);
		} 
		catch( InstantiationException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be concrete.";
			throw new ConfigurationException(errMsg, ex);
		} 
		catch( IllegalAccessException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must have a public, no-arg constructor.";
			throw new ConfigurationException(errMsg, ex);
		} 
		catch( ClassCastException ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") must be a subtype of T in ObjFactory<T>";
			throw new ConfigurationException(errMsg, ex);
		} 
		catch( Exception ex ) {
			errMsg = ex.toString() + " " + typeName + " class (" + className + ") CTOR threw exception.";
			throw new ConfigurationException(errMsg, ex);
		}
	}

	//Private non-instantiable constructor..
	private ObjFactory() { 

	}
}
