package com.gullerya.elsec;

import com.gullerya.elsec.api.SecuritySession;
import com.gullerya.elsec.api.SecurityService;
import com.gullerya.elsec.impl.SecurityFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

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
			Class<?> configurerClass;
			try {
				configurerClass = Class.forName(sConf);
			} catch (ClassNotFoundException cnfe) {
				throw new ServletException("failed to initialize configuration class '" + sConf + "'", cnfe);
			}
			try {
				for (Constructor<?> c : configurerClass.getDeclaredConstructors()) {
					if (c.getParameterCount() == 0) {
						configuration = (SecurityConfigurationSPI) c.newInstance();
					}
				}
			} catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
				throw new ServletException("failed to instantiate configuration class '" + sConf + "'", e);
			}
		}

		try {
			securityService = SecurityFactory.obtain(sKey, configuration);
		} catch (Exception e) {
			throw new ServletException("failed to obtain security service", e);
		}
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		try {
			SecuritySession securitySession = securityService.authenticate(request);
			if (securitySession != null) {
				boolean authorized = securityService.authorize(request, securitySession);
				if (authorized) {
					filterChain.doFilter(servletRequest, servletResponse);
				} else {
					response.sendError(HttpServletResponse.SC_FORBIDDEN);
				}
			} else {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			}
		} catch (Exception e) {
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
	}

	@Override
	public void destroy() {
	}
}
