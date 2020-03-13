package com.gullerya.elsec.api;

import javax.servlet.http.HttpServletRequest;

public interface SecurityService {
	String SERVICE_PARAM_KEY = "secSerKey";
	String SERVICE_CONFIG_KEY = "secSerConfig";
	String DEFAULT_SEC_SER_KEY = "default";

	SecuritySession authenticate(HttpServletRequest request) throws Exception;

	boolean authorize(HttpServletRequest request, SecuritySession securitySession);

	SecuritySession getContext(HttpServletRequest request);

	void createOTP();

	void verifyOTP();
}
