package com.gullerya.elsec.api;

import javax.servlet.http.HttpServletRequest;

public interface SessionsManager {

	SecuritySession obtainSession(HttpServletRequest request) throws Exception;
}
