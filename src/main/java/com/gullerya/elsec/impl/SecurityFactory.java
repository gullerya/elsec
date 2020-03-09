package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecurityService;

import java.util.HashMap;
import java.util.Map;

abstract public class SecurityFactory {
	private static final Map<String, SecurityService> secSers = new HashMap<>();

	private SecurityFactory() {
	}

	public static SecurityService obtain(String key, SecurityConfigurationSPI configuration) {
		if (key == null || key.isEmpty()) {
			throw new IllegalArgumentException("key MUST NOT be NULL nor EMPTY");
		}

		SecurityService result = secSers.get(key);
		if (result == null) {
			result = createSecurityService(key, configuration != null ? configuration : new SecurityConfigurationDefault());
		}
		return result;
	}

	public static SecurityService createSecurityService(String key, SecurityConfigurationSPI securityConfigurationSPI) {
		if (key == null || key.isEmpty()) {
			throw new IllegalArgumentException("key MUST NOT be NULL nor EMPTY");
		}
		if (secSers.containsKey(key)) {
			throw new IllegalArgumentException("security service with key '" + key + "' already exists");
		}

		SecurityService result = new SecurityServiceImpl(securityConfigurationSPI);
		secSers.put(key, result);
		return result;
	}

	public static SecurityService getSecurityService(String key) {
		if (key == null || key.isEmpty()) {
			throw new IllegalArgumentException("key MUST NOT be NULL nor EMPTY");
		}

		SecurityService result = secSers.get(key);
		if (result == null) {
			throw new IllegalStateException("no security service '" + key + "' present");
		} else {
			return result;
		}
	}
}
