package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecuritySession;
import com.gullerya.elsec.api.SessionsManager;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

abstract class SessionsManagerBaseImpl implements SessionsManager {
	private final String SA_KEY = UUID.randomUUID().toString();
	final SecurityConfigurationSPI configurer;

	SessionsManagerBaseImpl(SecurityConfigurationSPI configurer) {
		if (configurer == null) {
			throw new IllegalArgumentException("configurer MUST NOT be NULL");
		}
		this.configurer = configurer;
	}

	@Override
	public String serializeSession(SecuritySession session) {
		return "u:" + session.getUserId() + ",r:" + session.getRoles();
	}

	@Override
	public SecuritySession deserializeSession(String input) {
		Long userId = null, roles = null;
		String[] parts = input.split(",");
		for (String pair : parts) {
			String[] keyVal = pair.split(":");
			if ("u".equals(keyVal[0])) {
				userId = Long.parseLong(keyVal[1]);
			} else if ("r".equals(keyVal[0])) {
				roles = Long.parseLong(keyVal[1]);
			}
		}
		if (userId != null && roles != null) {
			return new SecuritySessionImpl(userId, roles);
		} else {
			return null;
		}
	}

	String getSecurityCookieValue(HttpServletRequest request) {
		if (request == null) {
			throw new IllegalArgumentException("request MUST NOT be NULL");
		}

		String result = null;
		String cookieName = configurer.getCookieName();
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (cookie.getName().compareTo(cookieName) == 0) {
					result = cookie.getValue();
					break;
				}
			}
		}
		return result;
	}

	void setSessionAttribute(HttpServletRequest request, SecuritySession session) {
		request.setAttribute(SA_KEY, session);
	}

	SecuritySession getSessionAttribute(HttpServletRequest request) {
		Object tmp = request.getAttribute(SA_KEY);
		if (tmp == null) {
			return null;
		} else {
			return (SecuritySession) tmp;
		}
	}
}
