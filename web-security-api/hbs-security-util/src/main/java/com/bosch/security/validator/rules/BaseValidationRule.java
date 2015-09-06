package com.bosch.security.validator.rules;

import com.bosch.security.codecs.Encoder;
import com.bosch.security.util.SecurityHandler;

/**
 * A ValidationRule performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 */
public abstract class BaseValidationRule implements ValidationRule 
{
	private String typeName = null;
	protected boolean allowNull = false;
	protected Encoder encoder = null;

	private BaseValidationRule() {

	}

	public BaseValidationRule(String typeName) {
		this();
		setEncoder(SecurityHandler.encoder());
		setTypeName( typeName );
	}

	public BaseValidationRule(String typeName, Encoder encoder ) {
		this();
		setEncoder( encoder );
		setTypeName( typeName );
	}

	@Override
	public void setAllowNull( boolean flag ) {
		allowNull = flag;
	}

	@Override
	public final void setTypeName( String typeName ) {
		this.typeName = typeName;
	}

	@Override
	public final void setEncoder( Encoder encoder ) {
		this.encoder = encoder;
	}

	public boolean isAllowNull() {
		return allowNull;
	}

	public Encoder getEncoder() {
		return encoder;
	}

	public String getTypeName() {
		return typeName;
	}
}
