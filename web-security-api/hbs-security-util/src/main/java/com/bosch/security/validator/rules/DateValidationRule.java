package com.bosch.security.validator.rules;

import java.text.DateFormat;
import java.util.Date;
import com.bosch.security.codecs.Encoder;
import com.bosch.security.errors.ValidationException;
import com.bosch.security.util.SecurityHandler;
import com.bosch.security.util.StringUtilities;


/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 */
public class DateValidationRule extends BaseValidationRule
{
	private DateFormat format = DateFormat.getDateInstance();

	public DateValidationRule(Encoder encoder, DateFormat newFormat )
	{
		/* For Date typeName is null */
		super( null, encoder );     

		// Set the date format..
		if (newFormat == null) {
			throw new IllegalArgumentException("DateValidationRule.setDateFormat requires a non-null DateFormat");
		}
		this.format = newFormat;
		this.format.setLenient( SecurityHandler.securityConfiguration().getLenientDatesAccepted());
	}

	@Override
	public Date getValid( String context, String input ) throws ValidationException {
		return safelyParse(context, input);
	}

	private Date safelyParse(String context, String input) throws ValidationException 
	{
		if (StringUtilities.isEmpty(input)) {
			if (allowNull) {
				return null;
			}
			throw new ValidationException(context + ": Input date required", "Input date required: context=" + context + ", input="
					+ input, context);
		}

		String canonical = encoder.canonicalize(input);
		try {
			return format.parse(canonical);
		}
		catch (Exception e) {
			throw new ValidationException(context + ": Invalid date must follow the " + format.getNumberFormat() + " format",
					"Invalid date: context=" + context + ", format=" + format
					+ ", input=" + input, e, context);
		}
	}
}