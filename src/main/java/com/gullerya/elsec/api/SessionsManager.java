package com.gullerya.elsec.api;

import javax.servlet.http.HttpServletRequest;

public interface SessionsManager {

	void createSession(HttpServletRequest request);

	void lookupSession(HttpServletRequest request);

	void removeSession();
}
