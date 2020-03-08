package com.gullerya.elsec;

import com.gullerya.elsec.api.*;

import javax.servlet.http.HttpServletRequest;

class SecurityServiceImpl implements SecurityService {
    private final PrincipalsManager principalsManager;
    private final SessionsManager sessionsManager;
    private final OTPManager otpManager;

    SecurityServiceImpl(SecuritySPI securitySPI) {
        principalsManager = securitySPI.getPrincipalsManager();
        sessionsManager = securitySPI.getSessionsManager();
        otpManager = securitySPI.getOTPManager();
    }

    @Override
    public void login() {

    }

    @Override
    public void logout() {

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
