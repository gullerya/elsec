package com.gullerya.elsec;

import com.gullerya.elsec.api.SecurityContext;
import com.gullerya.elsec.api.SecurityService;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
            authenticationErrorResponse(response, false);
        } else if ((securityToken = securityService.extractSecurityToken(securityCookie)) == null) {
            authenticationErrorResponse(response, true);
        } else if (securityToken.isExpired()) {
            authenticationErrorResponse(response, true);
        } else {
            refreshTokenIfRelevant(response, securityToken);
            SecurityContext securityContext = new ISureSecurityContextImpl(securityToken.userId, securityToken.userRoles);
            request.setAttribute(SecurityServiceImpl.SECURITY_CONTEXT_KEY, securityContext);
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {
    }

    private void authenticationErrorResponse(HttpServletResponse response, boolean removeToken) throws IOException {
        if (removeToken) {
            response.addCookie(SecurityService.createDisposalCookie());
        }
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void refreshTokenIfRelevant(HttpServletResponse response, SecurityServiceImpl.ISurePrincipal currentToken) {
        SecurityServiceImpl.ISurePrincipal renewed = currentToken.renewIfRelevant();
        if (renewed != null) {
            Cookie renewedCookie = securityService.createCookie(renewed);
            response.addCookie(renewedCookie);
        }
    }
}
