package com.isure.security;

import com.isure.security.api.SecurityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LogoutResource extends HttpServlet {
	private static final Logger logger = LoggerFactory.getLogger(LogoutResource.class);
	private static final String LOGOUT_PATH = "/logout";

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse res) {
		try {
			if (req.getServletPath().endsWith(LOGOUT_PATH)) {
				logout(res);
			} else {
				res.setStatus(HttpServletResponse.SC_NOT_FOUND);
			}
		} catch (Exception e) {
			logger.error("failed to process '" + req.getPathInfo() + "' request", e);
			res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
	}

	private void logout(HttpServletResponse res) {
		Cookie disposalCookie = SecurityService.createDisposalCookie();
		res.setStatus(HttpServletResponse.SC_OK);
		res.addCookie(disposalCookie);
	}
}
