package com.gullerya.elsec.api;

import javax.servlet.http.HttpServletRequest;

public interface SecurityService {

    void login();

    void logout();

    void createOTP();

    void verifyOTP();

    SecurityContext getContext(HttpServletRequest request);
}
