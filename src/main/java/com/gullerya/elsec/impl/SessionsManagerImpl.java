package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SessionsManager;

import javax.servlet.http.HttpServletRequest;

class SessionsManagerImpl implements SessionsManager {
	private final SecurityConfigurationSPI configurer;

	SessionsManagerImpl(SecurityConfigurationSPI configurer) {
		this.configurer = configurer;
	}

	@Override
	public void createSession(HttpServletRequest request) {
		if (request == null) {
			throw new IllegalArgumentException("request MUST NOT be NULL");
		}
		String cookieName = configurer.getCookieName();
	}

	@Override
	public void lookupSession(HttpServletRequest request) {

	}

	@Override
	public void removeSession() {

	}
}
