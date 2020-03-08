package com.gullerya.elsec;

import com.gullerya.elsec.api.SecurityService;

import java.util.HashMap;
import java.util.Map;

abstract public class SecurityFactory {
    private static final String DEFAULT_SEC_SER_KEY = "default";
    private static final Map<String, SecurityService> secSers = new HashMap<>();

    private SecurityFactory() {
    }

    public static SecurityService createSecurityService(SecuritySPI securitySPI) {
        return createSecurityService(DEFAULT_SEC_SER_KEY, securitySPI);
    }

    public static SecurityService createSecurityService(String key, SecuritySPI securitySPI) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("key MUST NOT be NULL nor EMPTY");
        }

        return null;
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
