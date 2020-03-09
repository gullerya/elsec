package com.gullerya.elsec.impl;

import com.gullerya.elsec.api.SecurityContext;

public class SecurityContextImpl implements SecurityContext {
	private final long userId;
	private final long userRoles;

	public SecurityContextImpl(long userId, long userRoles) {
		this.userId = userId;
		this.userRoles = userRoles;
	}

	@Override
	public long getUserId() {
		return userId;
	}

	@Override
	public long getUserRoles() {
		return userRoles;
	}

	@Override
	public boolean isUserInRole(long role) {
		return (userRoles & role) > 0;
	}
}
