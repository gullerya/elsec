package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.OTPManager;
import com.gullerya.elsec.api.PrincipalsManager;
import com.gullerya.elsec.api.SessionsManager;

public class SecurityConfigurationDefault implements SecurityConfigurationSPI {
	private final PrincipalsManager principalsManager;
	private final SessionsManager sessionsManager;
	private final OTPManager otpManager;
	private final String cookieName;
	private final String pass;

	protected SecurityConfigurationDefault() throws Exception {
		this(SecurityConfigurationSPI.DEFAULT_SECURITY_COOKIE_NAME, (String) null);
	}

	protected SecurityConfigurationDefault(String cookieName) throws Exception {
		this(cookieName, (String) null);
	}

	protected SecurityConfigurationDefault(String cookieName, String pass) throws Exception {
		this.cookieName = cookieName;
		this.pass = pass;
		principalsManager = new PrincipalsManagerImpl();
		sessionsManager = new EDSessionsManagerImpl(this);
		otpManager = new OTPManagerImpl();
	}

	private SecurityConfigurationDefault(SecurityConfigurationSPI customSPI) throws Exception {
		this(SecurityConfigurationSPI.DEFAULT_SECURITY_COOKIE_NAME, null, customSPI);
	}

	private SecurityConfigurationDefault(String cookieName, SecurityConfigurationSPI customSPI) throws Exception {
		this(cookieName, null, customSPI);
	}

	private SecurityConfigurationDefault(String cookieName, String pass, SecurityConfigurationSPI customSPI) throws Exception {
		this.cookieName = cookieName;
		this.pass = pass;
		principalsManager = customSPI.getPrincipalsManager() != null ? customSPI.getPrincipalsManager() : new PrincipalsManagerImpl();
		sessionsManager = customSPI.getSessionsManager() != null ? customSPI.getSessionsManager() : new EDSessionsManagerImpl(this);
		otpManager = customSPI.getOTPManager() != null ? customSPI.getOTPManager() : new OTPManagerImpl();
	}

	@Override
	public PrincipalsManager getPrincipalsManager() {
		return principalsManager;
	}

	@Override
	public SessionsManager getSessionsManager() {
		return sessionsManager;
	}

	@Override
	public OTPManager getOTPManager() {
		return otpManager;
	}

	@Override
	public String getCookieName() {
		return cookieName;
	}

	@Override
	public String getPass() {
		return pass;
	}
}
