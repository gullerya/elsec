package com.gullerya.elsec.api;

import javax.servlet.http.HttpServletRequest;

public interface SecurityService {

    SecurityContext authenticate(HttpServletRequest request);

    boolean authorize(HttpServletRequest request, SecurityContext securityContext);

    SecurityContext getContext(HttpServletRequest request);

    void createOTP();

    void verifyOTP();
}
