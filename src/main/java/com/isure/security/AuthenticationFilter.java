package com.isure.security;

import com.isure.security.api.SecurityService;
import com.isure.security.api.ISureSecurityContext;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import java.io.IOException;

public class AuthenticationFilter implements Filter {
	private static SecurityServiceImpl securityService;

	@Override
	public void init(FilterConfig filterConfig) {
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		if (securityService == null) {
			response.setStatus(HttpServletResponse.SC_PRECONDITION_FAILED);
			return;
		}

		String securityCookie = SecurityUtils.retrieveSecurityCookie(request.getCookies());
		SecurityServiceImpl.ISurePrincipal securityToken;
		if (securityCookie == null || securityCookie.isEmpty()) {
			authenticationErrorResponse(response, "token.missing", false);
		} else if ((securityToken = securityService.extractSecurityToken(securityCookie)) == null) {
			authenticationErrorResponse(response, "token.invalid", true);
		} else if (securityToken.isExpired()) {
			authenticationErrorResponse(response, "token.expired", true);
		} else {
			refreshTokenIfRelevant(response, securityToken);
			ISureSecurityContext securityContext = new ISureSecurityContextImpl(securityToken.userId, securityToken.userRoles);
			request.setAttribute(SecurityServiceImpl.SECURITY_CONTEXT_KEY, securityContext);
			filterChain.doFilter(servletRequest, servletResponse);
		}
	}

	@Override
	public void destroy() {
	}

	static void setSecurityService(SecurityServiceImpl securityService) {
		AuthenticationFilter.securityService = securityService;
	}

	private void authenticationErrorResponse(HttpServletResponse response, String errorType, boolean removeToken) throws IOException {
		if (removeToken) {
			response.addCookie(SecurityService.createDisposalCookie());
		}
		response.setContentType(MediaType.APPLICATION_JSON);
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, SecurityService.createErrorBody(errorType));
	}

	private void refreshTokenIfRelevant(HttpServletResponse response, SecurityServiceImpl.ISurePrincipal currentToken) {
		SecurityServiceImpl.ISurePrincipal renewed = currentToken.renewIfRelevant();
		if (renewed != null) {
			Cookie renewedCookie = securityService.createCookie(renewed);
			response.addCookie(renewedCookie);
		}
	}
}
