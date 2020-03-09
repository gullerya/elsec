package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.*;

import javax.servlet.http.HttpServletRequest;

class SecurityServiceImpl implements SecurityService {
	private final PrincipalsManager principalsManager;
	private final SessionsManager sessionsManager;
	private final OTPManager otpManager;

	SecurityServiceImpl(SecurityConfigurationSPI securityConfigurationSPI) {
		principalsManager = securityConfigurationSPI.getPrincipalsManager();
		sessionsManager = securityConfigurationSPI.getSessionsManager();
		otpManager = securityConfigurationSPI.getOTPManager();
	}

	@Override
	public SecurityContext authenticate(HttpServletRequest request) {
		return null;
	}

	@Override
	public boolean authorize(HttpServletRequest request, SecurityContext securityContext) {
		return false;
	}

	@Override
	public void createOTP() {

	}

	@Override
	public void verifyOTP() {

	}

	@Override
	public SecurityContext getContext(HttpServletRequest request) {
		return null;
	}
}
