package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecuritySession;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Encrypted Data strategy session management implementation
 */
class EDSessionsManagerImpl extends SessionsManagerBaseImpl {
	private final int keyIter = (int) Math.pow(2, 8);
	private final int keySize = 512;
	private final int randomPadSize = 11;

	private final Cipher encCipher;
	private final Cipher decCipher;

	EDSessionsManagerImpl(SecurityConfigurationSPI configurer) throws Exception {
		super(configurer);

		byte[] randomBytes = new byte[keySize / 8];
		new SecureRandom().nextBytes(randomBytes);
		SecretKey key = generateKey(configurer.getPass().toCharArray(), randomBytes, keyIter, keySize);
		encCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		encCipher.init(Cipher.ENCRYPT_MODE, key);
		decCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		encCipher.init(Cipher.DECRYPT_MODE, key);
	}

	@Override
	public SecuritySession obtainSession(HttpServletRequest request) throws Exception {
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

	private String encryptSession(SecuritySession securitySession) throws Exception {
		String serializedSession = serializeSecuritySession(securitySession);
		byte[] decBytes = serializedSession.getBytes(StandardCharsets.UTF_8);
		byte[] randomBytes = new byte[randomPadSize];
		new SecureRandom().nextBytes(randomBytes);
		byte[] allBytes = Arrays.copyOf(randomBytes, randomPadSize + decBytes.length);
		System.arraycopy(decBytes, 0, allBytes, randomBytes.length, decBytes.length);
		byte[] encBytes = encCipher.doFinal(allBytes);
		return Base64.getEncoder().encodeToString(encBytes);
	}

	private SecuritySession decryptSession(String ed) throws Exception {
		byte[] encBytes = Base64.getDecoder().decode(ed);
		byte[] decBytes = decCipher.doFinal(encBytes);
		return deserializeSecuritySession(new String(decBytes, randomPadSize, decBytes.length - randomPadSize, StandardCharsets.UTF_8));
	}

	private String serializeSecuritySession(SecuritySession securitySession) {
		return "u:" + securitySession.getUserId() + ",r:" + securitySession.getRoles();
	}

	private SecuritySession deserializeSecuritySession(String serializedSession) {
		Long userId = null, roles = null;
		String[] parts = serializedSession.split(",");
		for (String pair : parts) {
			String[] keyVal = pair.split(":");
			if ("u".equals(keyVal[0])) {
				userId = Long.parseLong(keyVal[1]);
			} else if ("r".equals(keyVal[0])) {
				roles = Long.parseLong(keyVal[1]);
			}
		}
		if (userId != null && roles != null) {
			return new SecuritySessionImpl(userId, roles);
		} else {
			return null;
		}
	}

	private SecretKey generateKey(char[] pass, byte[] salt, int iterations, int size) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA" + size);
		KeySpec spec = new PBEKeySpec(pass, salt, iterations, size);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}
}
