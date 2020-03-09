package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecuritySPI;
import com.gullerya.elsec.api.OTPManager;
import com.gullerya.elsec.api.PrincipalsManager;
import com.gullerya.elsec.api.SessionsManager;

public class SecuritySPIDefault implements SecuritySPI {
    private final PrincipalsManager principalsManager;
    private final SessionsManager sessionsManager;
    private final OTPManager otpManager;

    public SecuritySPIDefault() {
        principalsManager = new PrincipalsManagerImpl();
        sessionsManager = new SessionsManagerImpl();
        otpManager = new OTPManagerImpl();
    }

    private SecuritySPIDefault(SecuritySPI customSPI) {
        principalsManager = customSPI.getPrincipalsManager() != null ? customSPI.getPrincipalsManager() : new PrincipalsManagerImpl();
        sessionsManager = customSPI.getSessionsManager() != null ? customSPI.getSessionsManager() : new SessionsManagerImpl();
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
