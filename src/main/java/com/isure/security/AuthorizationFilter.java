package com.isure.security;

import com.isure.security.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;

@Component
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {

	@Context
	private ResourceInfo resourceInfo;
	@Context
	private HttpServletRequest request;
	@Autowired
	private SecurityService securityService;

	@Override
	public void filter(ContainerRequestContext context) {
		Authorized authorized = resourceInfo.getResourceMethod().getDeclaredAnnotation(Authorized.class);
		if (authorized != null) {
			List<UserRole> allowedRoles = Arrays.asList(authorized.value());
			if (allowedRoles.contains(UserRole.ANY)) {
				return;
			}

			ISureSecurityContext securityContext = securityService.getRequestSecurityContext(request);
			if (securityContext == null) {
				Response r = authorizationErrorResponse("unauthenticated");
				context.abortWith(r);
			} else if (allowedRoles.stream().noneMatch(securityContext::isUserInRole)) {
				Response r = authorizationErrorResponse("unauthorized");
				context.abortWith(r);
			}
		} else {
			throw new RuntimeException("authorization is not defined for the resource '" + resourceInfo.getResourceMethod() + "'");
		}
	}

	private Response authorizationErrorResponse(String errorType) {
		return Response
				.status(Response.Status.FORBIDDEN)
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
				.entity(SecurityService.createErrorBody(errorType))
				.build();
	}
}
