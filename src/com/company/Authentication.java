package com.company;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Created by noboud_n on 31/10/2016.
 */

public class Authentication {

    Authentication() {};

	private String truncateHash(byte[] hash) {
		String hashString = new String(hash);
		int offset = Integer.parseInt(hashString.substring(hashString.length() - 1, hashString.length()), 16);

		String truncatedHash = hashString.substring(offset * 2, offset * 2 + 8);

		int val = Integer.parseUnsignedInt(truncatedHash, 16) & 0x7FFFFFFF;

		String finalHash = String.valueOf(val);
		finalHash = finalHash.substring(finalHash.length() - 6, finalHash.length());

		return finalHash;
	}

	private byte[] hmacSha1(byte[] value, byte[] keyBytes) {
		SecretKeySpec signKey = new SecretKeySpec(keyBytes, "HmacSHA1");
		try {
			Mac mac = Mac.getInstance("HmacSHA1");

			mac.init(signKey);

			byte[] rawHmac = mac.doFinal(value);

			return new Hex().encode(rawHmac);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String GoogleAuthenticatorCode(String secret) throws Exception {
		long value = new Date().getTime() / TimeUnit.SECONDS.toMillis(30);

		base32 base = new base32(base32.Alphabet.BASE32, false, true);
		byte[] key = base.fromString(secret);

		System.out.println(Arrays.toString(key));

		byte[] data = new byte[8];
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		byte[] hash = hmacSha1(data, key);

		return truncateHash(hash);
	}

	public static void main(String[] args) {
		Authentication auth = new Authentication();

		try {
			System.out.println(auth.GoogleAuthenticatorCode("2xmzih2yhhgpvnqrnv2t5fnxuk4stps6"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
