package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.OTPManager;
import com.gullerya.elsec.api.PrincipalsManager;
import com.gullerya.elsec.api.SessionsManager;

public class SecurityConfigurationDefault implements SecurityConfigurationSPI {
    private final PrincipalsManager principalsManager;
    private final SessionsManager sessionsManager;
    private final OTPManager otpManager;

    protected SecurityConfigurationDefault() {
        principalsManager = new PrincipalsManagerImpl();
        sessionsManager = new EDSessionsManagerImpl(this);
        otpManager = new OTPManagerImpl();
    }

    private SecurityConfigurationDefault(SecurityConfigurationSPI customSPI) {
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
        return "sid";
    }
}
