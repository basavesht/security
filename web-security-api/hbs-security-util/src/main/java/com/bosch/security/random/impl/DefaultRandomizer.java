package com.bosch.security.random.impl;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Timer;
import java.util.TimerTask;

import com.bosch.security.errors.EncryptionException;
import com.bosch.security.random.Randomizer;
import com.bosch.security.util.SecurityHandler;

/**
 * Reference implementation of the Randomizer interface. This implementation builds on the JCE provider to provide a
 * cryptographically strong source of entropy. 
 */
public class DefaultRandomizer implements Randomizer
{
	private static volatile Randomizer singletonInstance;
	private static final long seedResetPeriod = 120*(60*60*24*1000);  //Seed reset period set to 4 months..
	private static final long seedResetDelay = 120*(60*60*24*1000);  //Seed reset period set to 4 months..
	private SecureRandom secureRandom = null;

	//Re-seed randomizer instance every 3 months...
	static {
		Timer timer = new Timer();
		timer.schedule(new TimerTask() {
			public void run() {
				synchronized(DefaultRandomizer.class) {
					singletonInstance = new DefaultRandomizer();
				}
			}
		}, seedResetDelay, seedResetPeriod /* Once every 4 months */);
	}

	public static Randomizer getInstance() {
		if (singletonInstance == null) {
			synchronized (DefaultRandomizer.class ) {
				if (singletonInstance == null) {
					singletonInstance = new DefaultRandomizer();
				}
			}
		}
		return singletonInstance;
	}

	private DefaultRandomizer() {
		String algorithm = SecurityHandler.securityConfiguration().getRandomAlgorithm();
		try {
			secureRandom = SecureRandom.getInstance(algorithm, "SUN");
			getRandomBytes(8); //This will force the PRNG to seed itself securely...
		}
		catch (NoSuchAlgorithmException e) { //Can't throw exception from constructor...
			new EncryptionException("Error creating randomizer", "Can't find random algorithm " + algorithm, e);
		} 
		catch (NoSuchProviderException e) {
			new EncryptionException("Error creating randomizer", "Can't find security provider " + algorithm, e);

		}
	}

	@Override
	public String getRandomString(int length, char[] characterSet) {
		StringBuilder sb = new StringBuilder();
		for (int loop = 0; loop < length; loop++) {
			int index = secureRandom.nextInt(characterSet.length);
			sb.append(characterSet[index]);
		}
		String nonce = sb.toString();
		return nonce;
	}

	@Override
	public boolean getRandomBoolean() {
		return secureRandom.nextBoolean();
	}

	@Override
	public int getRandomInteger(int min, int max) {
		return secureRandom.nextInt(max - min) + min;
	}

	@Override
	public long getRandomLong() {
		return secureRandom.nextLong();    
	}

	@Override
	public float getRandomReal(float min, float max) {
		float factor = max - min;
		return secureRandom.nextFloat() * factor + min;
	}

	@Override
	public byte[] getRandomBytes(int n) {
		byte[] result = new byte[ n ];
		secureRandom.nextBytes(result);
		return result;
	}
}
