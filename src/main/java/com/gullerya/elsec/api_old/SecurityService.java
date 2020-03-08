package com.gullerya.elsec.api_old;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;

public interface SecurityService {
	String SECURITY_COOKIE_NAME = "isure.st";

	SecretKey generateKey() throws Exception;

	SecretKey generateKey(String pass, String salt) throws Exception;

	Cookie createCookie(long userId, long roles);

	byte[] encrypt(String input, SecretKey key) throws Exception;

	String decrypt(byte[] input, SecretKey key) throws Exception;

	String hashPass(String pass);

	boolean verifyPass(String candidate, String hash);

	ISureSecurityContext getRequestSecurityContext(HttpServletRequest request);

	long getRequestUserId(HttpServletRequest request);

	static String createErrorBody(String errorType) {
		return "{\"errorType\":\"" + errorType + "\"}";
	}

	static Cookie createDisposalCookie() {
		Cookie result = new Cookie(SECURITY_COOKIE_NAME, "tbr");
		result.setDomain("");
		result.setPath("/");
		result.setMaxAge(0);
		result.setSecure(false);
		result.setHttpOnly(true);
		return result;
	}
}
