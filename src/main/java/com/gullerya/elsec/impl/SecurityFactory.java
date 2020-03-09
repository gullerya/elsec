package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecurityService;

import java.util.HashMap;
import java.util.Map;

abstract public class SecurityFactory {
	private static final Map<String, SecurityService> secSers = new HashMap<>();
	static final String DEFAULT_SEC_SER_KEY = "default";

	private SecurityFactory() {
	}

	public static SecurityService createSecurityService() {
		return createSecurityService(new SecurityConfigurationDefault());
	}

	public static SecurityService createSecurityService(SecurityConfigurationSPI securityConfigurationSPI) {
		return createSecurityService(DEFAULT_SEC_SER_KEY, securityConfigurationSPI);
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

	public static SecurityService getSecurityService() {
		return getSecurityService(DEFAULT_SEC_SER_KEY);
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
