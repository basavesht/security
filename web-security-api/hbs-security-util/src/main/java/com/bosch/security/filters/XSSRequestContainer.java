package com.bosch.security.filters;

import java.util.Map;

public class XSSRequestContainer {

	private Map<String, String[]> headers ;
	private Map<String, String[]> body ;
	private Map<String, String[]> queryString ;
	
	public Map<String, String[]> getHeaders() {
		return headers;
	}
	public void setHeaders(Map<String, String[]> headers) {
		this.headers = headers;
	}
	public Map<String, String[]> getBody() {
		return body;
	}
	public void setBody(Map<String, String[]> body) {
		this.body = body;
	}
	public Map<String, String[]> getQueryString() {
		return queryString;
	}
	public void setQueryString(Map<String, String[]> queryString) {
		this.queryString = queryString;
	}
}
