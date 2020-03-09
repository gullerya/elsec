package com.gullerya.elsec.api;

public interface SecurityContext {

	long getUserId();

	long getRoles();

	boolean isUserInRole(long role);
}
