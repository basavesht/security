package com.bosch.security.logger;

import com.bosch.security.errors.IntrusionException;

/**
 * The IntrusionDetector interface is intended to track security relevant events and identify attack behavior. The
 * implementation can use as much state as necessary to detect attacks, but note that storing too much state will burden
 * your system.
 * <P>
 * The interface is currently designed to accept exceptions as well as custom events. Implementations can use this
 * stream of information to detect both normal and abnormal behavior.
 */
public interface IntrusionDetector {

    /**
     * Adds the exception to the IntrusionDetector.  This method should immediately log the exception so that developers throwing an 
     * IntrusionException do not have to remember to log every error.  The implementation should store the exception somewhere for the current user
     * in order to check if the User has reached the threshold for any Enterprise Security Exceptions.  The User object is the recommended location for storing
     * the current user's security exceptions.  If the User has reached any security thresholds, the appropriate security action can be taken and logged.
     * @param exception the exception thrown
     * @throws IntrusionException the intrusion exception
     */
    void addException(Exception exception) throws IntrusionException;

    /**
     * Adds the event to the IntrusionDetector.  This method should immediately log the event.  The implementation should store the event somewhere for the current user
     * in order to check if the User has reached the threshold for any Enterprise Security Exceptions.  The User object is the recommended location for storing
     * the current user's security event.  If the User has reached any security thresholds, the appropriate security action can be taken and logged.
     * @param eventName the event to add
     * @param logMessage the message to log with the event
     * @throws IntrusionException 
     * 		the intrusion exception
     */
    void addEvent(String eventName, String logMessage) throws IntrusionException;

}
