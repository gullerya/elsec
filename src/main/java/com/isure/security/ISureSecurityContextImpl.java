package com.isure.security;

import com.isure.security.api.ISureSecurityContext;
import com.isure.security.api.UserRole;

class ISureSecurityContextImpl implements ISureSecurityContext {
	private final long userId;
	private final long userRoles;

	ISureSecurityContextImpl(long userId, long userRoles) {
		this.userId = userId;
		this.userRoles = userRoles;
	}

	@Override
	public long getUserId() {
		return userId;
	}

	@Override
	public boolean isUserInRole(UserRole userRole) {
		if (userRole == null) {
			throw new IllegalArgumentException("user role MUST NOT be NULL");
		}
		return (userRoles & userRole.getValue()) > 0;
	}
}
