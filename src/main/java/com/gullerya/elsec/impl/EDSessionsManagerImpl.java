package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecuritySession;

import javax.servlet.http.HttpServletRequest;

/**
 * Encrypted data session manager
 * This is an ED strategy session management implementation
 */
class EDSessionsManagerImpl extends SessionsManagerBaseImpl {

	EDSessionsManagerImpl(SecurityConfigurationSPI configurer) {
		super(configurer);
	}

	@Override
	public SecuritySession obtainSession(HttpServletRequest request) {
		SecuritySession result = getSessionAttribute(request);
		if (result == null) {
			String ed = getSecurityCookieValue(request);
			if (ed != null && !ed.isEmpty()) {
				result = decryptSession(ed);
				if (result != null) {
					setSessionAttribute(request, result);
				}
			}
		}
		return result;
	}

	private String encryptSession(SecuritySession securitySession) {
		return null;
	}

	private SecuritySession decryptSession(String ed) {
		return null;
	}
}
