package com.gullerya.elsec;

import com.gullerya.elsec.api.SecurityContext;
import com.gullerya.elsec.api.SecurityService;
import com.gullerya.elsec.impl.SecurityFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecurityFilter implements Filter {
	private SecurityService securityService;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		//  service key
		String sKey = filterConfig.getInitParameter(SecurityService.SERVICE_PARAM_KEY);
		if (sKey != null) {
			if (sKey.isEmpty()) {
				throw new IllegalStateException("security service key parameter MUST NOT be EMPTY");
			}
		} else {
			sKey = SecurityService.DEFAULT_SEC_SER_KEY;
		}

		//  service configuration
		SecurityConfigurationSPI configuration = null;
		String sConf = filterConfig.getInitParameter(SecurityService.SERVICE_CONFIG_KEY);
		if (sConf != null) {
			Class<SecurityConfigurationSPI> configurerClass;
			try {
				configurerClass = (Class<SecurityConfigurationSPI>) Class.forName(sConf);
			} catch (ClassNotFoundException cnfe) {
				throw new ServletException("failed to initialize configuration class '" + sConf + "'", cnfe);
			}
			try {
				configuration = configurerClass.newInstance();
			} catch (IllegalAccessException | InstantiationException iae) {
				throw new ServletException("failed to instantiate configuration class '" + sConf + "'", iae);
			}
		}

		securityService = SecurityFactory.obtain(sKey, configuration);
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

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
