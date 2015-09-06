package com.bosch.security.util;

public enum ValidationType 
{
	ACCOUNT_NAME ("AccountName"),
	SYSTEM_COMMAND ("SystemCommand"),
	ROLE_NAME ("RoleName"),
	REDIRECT ("Redirect"),
	SAFE_STRING ("SafeString"),
	EMAIL ("Email"),
	IP_ADDRESS ("IPAddress"),
	URL ("URL"),
	CREDI_TCARD ("CreditCard"),
	SSN ("SSN"),
	FILE_NAME ("FileName"),
	DIRECTORY_NAME ("DirectoryName"),

	HTTP_SCHEME ("HTTPScheme"),
	HTTP_SERVERNAME ("HTTPServerName"),
	HTTP_COOKIENAME ("HTTPCookieName"),
	HTTP_COOKIEVALUE ("HTTPCookieValue"),
	HTTP_HEADERNAME ("HTTPHeaderName"),
	HTTP_HEADERVALUE ("HTTPHeaderValue"),
	HTTP_SERVLETPATH ("HTTPServletPath"),
	HTTP_PATH ("HTTPPath"),
	HTTP_URL ("HTTPURL"),
	HTTP_JSESSIONID ("HTTPJSESSIONID"),
	HTTP_PARAMETERNAME ("HTTPParameterName"),
	HTTP_PARAMETERVALUE ("HTTPParameterValue"),
	HTTP_CONTEXTPATH ("HTTPContextPath"),
	HTTP_QUERYSTRING ("HTTPQueryString"),
	HTTP_URI ("HTTPURI");

	String type = null;
	private  ValidationType (String type) {
		this.type = type;
	}

	public String getType() {
		return type;
	}
}
