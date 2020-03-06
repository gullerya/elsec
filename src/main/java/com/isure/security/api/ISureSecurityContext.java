package com.isure.security.api;

public interface ISureSecurityContext {

	long getUserId();

	boolean isUserInRole(UserRole userRole);
}
