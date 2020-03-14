package com.gullerya.elsec;

import com.gullerya.elsec.api.OTPManager;
import com.gullerya.elsec.api.PrincipalsManager;
import com.gullerya.elsec.api.SessionsManager;

public interface SecurityConfigurationSPI {

	PrincipalsManager getPrincipalsManager();

	SessionsManager getSessionsManager();

	OTPManager getOTPManager();

	String getCookieName();

	String getPass();
}
