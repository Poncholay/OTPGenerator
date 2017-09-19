package com.requireris.app.web.rest;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Created by wilmot_g on 31/10/2016.
 */

public class Authentication {

    Authentication() {};

	//For more informations, see : https://en.wikipedia.org/wiki/Google_Authenticator#Pseudocode_for_one-time_password_.28OTP.29
	
	/**
	 * Truncates the hash.
	 * @param hash The hash.
	 * @return The truncated hash as a String.
	 */
	private String truncateHash(byte[] hash) {
		String hashString = new String(hash);
		
		//Last nibble of hash
		int offset = Integer.parseInt(hashString.substring(hashString.length() - 1, hashString.length()), 16);

		//Truncate hash
		String truncatedHash = hashString.substring(offset * 2, offset * 2 + 8);

		//Convert hash to int and remove the most significant bit
		int val = Integer.parseUnsignedInt(truncatedHash, 16) & 0x7FFFFFFF;

		//Convert hash back to String
		String finalHash = String.valueOf(val);
		
		//Keep the last 6 digits
		finalHash = finalHash.substring(finalHash.length() - 6, finalHash.length());

		return finalHash;
	}

	/**
	 * Performs a hmacSha1 encode on a byte array.
	 * @param value The array to encode.
	 * @param keyBytes The key used to encode.
	 * @return The encoded byte array.
	 */
	private byte[] hmacSha1(byte[] value, byte[] keyBytes) {
		SecretKeySpec signKey = new SecretKeySpec(keyBytes, "HmacSHA1");
		try {
			//Get hmacSha1 algorithm
			Mac mac = Mac.getInstance("HmacSHA1");

			//Provide algorithm with key
			mac.init(signKey);

			//Encode value to hmacSha1
			byte[] rawHmac = mac.doFinal(value);

			//Encode result to Hexadecimal
			return new Hex().encode(rawHmac);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generates a one time password to use with Google's two steps authentication.
	 * @param secret The client secret. A unique private id used to generate the one time password.
	 * @return The one time password.
	 */
	public String GoogleAuthenticatorCode(String secret) throws Exception {
		if (secret == null || secret == "") {
			throw new Exception("Secret key does not exist.");
		}
		
		//Current Unix time / 30 
		long value = new Date().getTime() / TimeUnit.SECONDS.toMillis(30);

		//Encode secret to base32
		Base32 base = new Base32(Base32.Alphabet.BASE32, false, true);
		byte[] key = base.fromString(secret);

		//Convert value to byte array
		byte[] data = new byte[8];
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		//Encode data with key using hmacSha1 algorithm to get hash
		byte[] hash = hmacSha1(data, key);

		//Truncate resulting hash
		return truncateHash(hash);
	}
}
