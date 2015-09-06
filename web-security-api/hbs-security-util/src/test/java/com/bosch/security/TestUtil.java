package com.bosch.security;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.security.crypto.EncryptionUtils;
import com.bosch.security.errors.EncryptionException;
import com.bosch.security.random.SecureRandomUtils;
import com.bosch.security.validator.ValidationUtils;

public class TestUtil 
{
	private static Logger logger = LoggerFactory.getLogger(TestUtil.class);

	public static void main (String... args) throws UnsupportedEncodingException
	{
		//Encryption/Decryption 
		String[] inputData={"<script>(.*?)</script>",
				"src[\r\n]*=[\r\n]*\\\'(.*?)\\\'",
				"src[\r\n]*=[\r\n]*\\\"(.*?)\\\"",
				"javascript:(99)",
				"eval(1)",
				"expression(abc)",
				"vbscript:",
				"onload(.*?)=",
				"%3383492837489jhdfjksf_ najk~!@#$%^&*(){}\":<>?[]|;\'.,t%est<script>\\",
				"Hello World : src='http://asdasd'",
				"%3383492837489jhdfjksf_ najk~!@#$%^&*(){}\":<>?[]|;\'.,t%est<asdasdasd>\\",
				"23423423",
				"sdf\nsdf24\n523423",
				"%~!@#$%^&*()_+}{\":?<>/.,;\'[]=-0987654321`'",
				"mypassword\\1",
				"Comment\t",
				"C:\\Trainings\\Bosch\\Quality\\read.txt",
				"<SCRIPT>(.*?)</SCRIPT>",
				"Microlife&reg; character sdf™ &copy; &trade; &reg; Company Name®  sdf© $ Dollar, € Euro, ¥ Yen PF-100 (USB) á ì ñ ô(not for use with HB1)",
				"[{\"itemName\":\"''/001_Welcome&#;&Intros\",\"scheduleStart\":\"Session 1\",\"scheduleRun\":\"Every Session\",\"scheduledFor\":\"Entire Schedule\",\"scheduleSelect\":\"1 Dialogues\",\"scheduleDuration\":\"3\",\"schedulePrefix\":\"Session\",\"start\":\"1\",\"period\":\"1\",\"duration\":\"0\",\"schedulemode\":\"DIALOGUES\",\"mode\":\"DIALOGUES\",\"numselected\":\"1\",\"content\":\"76850\",\"floating\":\"false\",\"scheduleTreeNodePath\":\"/21040/76850\"}]",
				"&inty"
		};
		
		for (int i = 0; i < inputData.length; i++) {
			try { 
				SecretKey secretKey = EncryptionUtils.getSecretKey();
				String encryptedData = EncryptionUtils.encrypt(secretKey,inputData[i]);
				String decryptedData = EncryptionUtils.decrypt(secretKey, encryptedData);
				if(decryptedData.equals(inputData[i])){
					logger.debug("Encrypt/Decrypt successfull");
					System.out.println("Encrypt/Decrypt successfull");
				}
			}
			catch (EncryptionException e) {
				logger.debug("Encryption Failed..");
				e.printStackTrace();
			}
		}

		//Validate using white list pattern for HTTPPrameterValue type (Configurable)
		for(int i = 0 ; i < inputData.length ; i++) {
			boolean isValidHTTParameter = false;
			try {
				isValidHTTParameter = ValidationUtils.isValidHTTPParam(inputData[i],true);
				logger.debug("HTTP parameter : " + inputData[i] + " = " + isValidHTTParameter);
				System.out.println("HTTP parameter : " + inputData[i] + " = " + isValidHTTParameter);
			} catch (Exception e) {
				logger.error("isValidHTTParameter" + isValidHTTParameter);
			}
		}

		//Generate encode XSS patterns..
		String[] patternStrings={"<script>(.*?)</script>",
				"src[\r\n]*=[\r\n]*\\\'(.*?)\\\'",
				"src[\r\n]*=[\r\n]*\\\"(.*?)\\\"",
				"javascript:(.*?)",
				"((\\%3C)|<)((\\%2F)|\\/)script((\\%3E)|>)",
				"((\\%3C)|<)script(.*?)((\\%3E)|>)",
				"eval\\((.*?)\\)",
				"expression\\((.*?)\\)",
				"vbscript:",
				"onload(.*?)=",
				"((\\%3C)|<)((\\%69)|i|(\\%49))((\\%6D)|m|(\\%4D))((\\%67)|g|(\\%47))[^\\n]",
				"((\\%3C)|<)((\\%69)|i|(\\%49))((\\%46)|f|(\\%66))((\\%52)|r|(\\%72))((\\%41)|a|(\\%61))((\\%6D)|m|(\\%4D))((\\%45)|e|(\\%65))[^\\n]",
				"((\\%3C)|<)((\\%4F)|o|(\\%6F))((\\%42)|b|(\\%62))((\\%4A)|j|(\\%6A))((\\%45)|e|(\\%65))((\\%43)|c|(\\%63))((\\%54)|t|(\\%74))[^\\n]",
				"((\\%3C)|<)((\\%45)|e|(\\%65))((\\%6D)|m|(\\%4D))((\\%42)|b|(\\%62))((\\%45)|e|(\\%65))((\\%44)|d|(\\%64))[^\\n]"
		};

		//Validate using white list pattern for HTTPPrameterValue type (Configurable)
		for(int i = 0 ; i < patternStrings.length ; i++) {
			String encodedPattern = Base64.encodeBase64String(patternStrings[i].getBytes(StandardCharsets.UTF_8));
			logger.debug("XSS.Pattern." + i+ "=\"" + encodedPattern + "\"");
		}

		//Validate SSN
		boolean isValidSSN;
		isValidSSN = ValidationUtils.isValidSSN("0780591120");
		logger.debug("SSN Valid :" + isValidSSN);

		//Hashing 
		String password =  "Hello@123";
		String salt = EncryptionUtils.getSalt();
		logger.debug("Salt  " + salt);
		try {
			String hash1 = EncryptionUtils.hash(password, salt);
			String hash2 = EncryptionUtils.hash(password, salt);
			logger.debug("SHA 256 Hash  " + hash1);
			if(hash1.equals(hash2)) {
				logger.debug("Password matched ");
			}

			//MD5 Hashing..
			logger.debug("MD5 Hash  "+ DigestUtils.md5Hex(salt + password));
		} 
		catch (EncryptionException e) {
			e.printStackTrace();
		}

		//Validate Date
		boolean isValidDate;
		DateFormat dt = new SimpleDateFormat("MM/dd/yyyy");
		isValidDate = ValidationUtils.isValidDate("08/26/2014", dt);
		logger.debug("isValidDate :" + isValidDate);

		String sessionId = SecureRandomUtils.getRandomSessionId();
		Long randomlong = SecureRandomUtils.getRandomLong();
		logger.debug(sessionId + randomlong);
		
		//Validate FileName 
		List<String> allowedExtensions = Arrays.asList("");
		String fileName = "read.txt";
		System.out.println("Valid filename " + ValidationUtils.isValidFileName(fileName, allowedExtensions));
		
		String directoryPath = "C:\\Workspace\\Code\\Repository\\HBS\\Security\\hbs-security-util\\src\\main\\java\\com\\bosch\\security\\util";
		System.out.println("Valid directory path " + ValidationUtils.isValidDirectoryPath(directoryPath));
		
	}
	
	{
		System.out.println(" *************************************  *************************** ^^^^^^^^^^^^^^^^^^^^^^^^^ test");
	}
}
