package com.gullerya.elsec;

import com.gullerya.elsec.api.SecurityContext;
import com.gullerya.elsec.api.SecurityService;
import com.gullerya.elsec.impl.SecurityFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecurityFilter implements Filter {
	private static final String SERVICE_PARAM_KEY = "securityServiceKey";
	private String securityServiceKey = SecurityFactory.DEFAULT_SEC_SER_KEY;

	@Override
	public void init(FilterConfig filterConfig) {
		String sKey = filterConfig.getInitParameter(SERVICE_PARAM_KEY);
		if (sKey != null) {
			if (sKey.isEmpty()) {
				throw new IllegalStateException("security service key parameter MUST NOT be EMPTY");
			}
			securityServiceKey = sKey;
		}
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		SecurityService securityService = SecurityFactory.getSecurityService(securityServiceKey);

		SecurityContext securityContext = securityService.authenticate(request);
		if (securityContext != null) {
			boolean authorized = securityService.authorize(request, securityContext);
			if (authorized) {
				filterChain.doFilter(servletRequest, servletResponse);
			} else {
				response.sendError(HttpServletResponse.SC_FORBIDDEN);
			}
		} else {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		}
	}

	@Override
	public void destroy() {
	}
}
