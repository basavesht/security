package com.bosch.security.logger;

/**
 * Defines the type of log event that is being generated. 
 * The Logger interface defines 6 types of Log events: SECURITY_SUCCESS, SECURITY_FAILURE, 
 * EVENT_SUCCESS, EVENT_FAILURE, EVENT_UNSPECIFIED.
 * Your implementation can extend or change this list if desired. 
 */
public enum EventType 
{
	SECURITY_SUCCESS("SECURITY_SUCCESS"),
	SECURITY_FAILURE("SECURITY_FAILURE"),
	SECURITY_AUDIT("SECURITY_AUDIT"),
	EVENT_SUCCESS("EVENT_SUCCESS"),
	EVENT_FAILURE("EVENT_FAILURE"),
	EVENT_UNSPECIFIED("EVENT_UNSPECIFIED");

	String event = null;
	private EventType (String event) {
		this.event  = event;
	}

	public String getEvent() {
		return this.event;
	}
}
