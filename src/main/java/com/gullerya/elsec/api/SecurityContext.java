package com.gullerya.elsec.api;

public interface SecurityContext {

	long getUserId();

	long getUserRoles();

	boolean isUserInRole(long role);
}
