package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.*;

import javax.servlet.http.HttpServletRequest;

class SecurityServiceImpl implements SecurityService {
	private final PrincipalsManager principalsManager;
	private final SessionsManager sessionsManager;
	private final OTPManager otpManager;

	SecurityServiceImpl(SecurityConfigurationSPI securityConfiguration) {
		if (securityConfiguration == null) {
			throw new IllegalArgumentException("security configuration MUST NOT be NULL");
		}
		principalsManager = securityConfiguration.getPrincipalsManager();
		sessionsManager = securityConfiguration.getSessionsManager();
		otpManager = securityConfiguration.getOTPManager();
	}

	@Override
	public SecuritySession authenticate(HttpServletRequest request) throws Exception {
		return sessionsManager.obtainSession(request);
	}

	@Override
	public boolean authorize(HttpServletRequest request, SecuritySession securitySession) {
		return false;
	}

	@Override
	public void createOTP() {

	}

	@Override
	public void verifyOTP() {

	}

	@Override
	public SecuritySession getContext(HttpServletRequest request) {
		return null;
	}
}
