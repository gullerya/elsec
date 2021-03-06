package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecurityService;

import java.util.HashMap;
import java.util.Map;

abstract public class SecurityFactory {
	private static final Object SERVICE_INIT_LOCK = new Object();
	private static final Map<String, SecurityService> secSers = new HashMap<>();

	private SecurityFactory() {
	}

	public static SecurityService obtain(String key, SecurityConfigurationSPI configuration) throws Exception {
		if (key == null || key.isEmpty()) {
			throw new IllegalArgumentException("key MUST NOT be NULL nor EMPTY");
		}

		SecurityService result = secSers.get(key);
		if (result == null) {
			synchronized (SERVICE_INIT_LOCK) {
				if (!secSers.containsKey(key)) {
					result = createSecurityService(key, configuration != null ? configuration : new SecurityConfigurationDefault());
				}
			}
		}
		return result;
	}

	private static SecurityService createSecurityService(String key, SecurityConfigurationSPI securityConfigurationSPI) {
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
}
