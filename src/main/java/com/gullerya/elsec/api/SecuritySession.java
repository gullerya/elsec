package com.gullerya.elsec.api;

public interface SecuritySession {

	long getUserId();

	long getRoles();

	boolean isUserInRole(long role);
}
