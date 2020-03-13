package com.gullerya.elsec.impl;

import com.gullerya.elsec.api.SecuritySession;

public class SecuritySessionImpl implements SecuritySession {
	private final long userId;
	private final long roles;

	public SecuritySessionImpl(long userId, long roles) {
		this.userId = userId;
		this.roles = roles;
	}

	@Override
	public long getUserId() {
		return userId;
	}

	@Override
	public long getRoles() {
		return roles;
	}

	@Override
	public boolean isUserInRole(long role) {
		return (roles & role) > 0;
	}
}
