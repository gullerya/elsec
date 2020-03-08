package com.isure.security;

import com.isure.security.api.SecurityService;

import javax.servlet.http.Cookie;

abstract class SecurityUtils {

	private SecurityUtils() {
	}

	static String retrieveSecurityCookie(Cookie[] cookies) {
		String result = null;
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (SecurityService.SECURITY_COOKIE_NAME.equals(cookie.getName())) {
					result = cookie.getValue();
					break;
				}
			}
		}
		return result;
	}
}
