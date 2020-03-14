package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecuritySession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * Encrypted Data strategy session management implementation
 */
class EDSessionsManagerImpl extends SessionsManagerBaseImpl {
	private static final Logger logger = LoggerFactory.getLogger(EDSessionsManagerImpl.class);
	private final String passPhrase;
	private final Cipher encCipher;
	private final Cipher decCipher;

	EDSessionsManagerImpl(SecurityConfigurationSPI configurer) throws Exception {
		super(configurer);
		if (configurer.getPass() != null && !configurer.getPass().isEmpty()) {
			passPhrase = configurer.getPass();
		} else {
			logger.warn("ED session manager initialized with a RANDOM pass-phrase");
			passPhrase = UUID.randomUUID().toString();
		}

		long startTime = System.currentTimeMillis();
		byte[] randomBytes = new byte[16];
		new SecureRandom().nextBytes(randomBytes);
		SecretKey key = generateKey(getPassPhrase().toCharArray(), randomBytes, getKeyIter(), getKeySize());
		encCipher = Cipher.getInstance(getCipherAlgo());
		encCipher.init(Cipher.ENCRYPT_MODE, key);
		decCipher = Cipher.getInstance(encCipher.getAlgorithm());
		decCipher.init(Cipher.DECRYPT_MODE, key, encCipher.getParameters().getParameterSpec(IvParameterSpec.class));
		logger.info(this.getClass().getName() + " initialized in " + (System.currentTimeMillis() - startTime) + " ms");
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

	public String getPassPhrase() {
		return passPhrase;
	}

	protected String getCipherAlgo() {
		return "AES/CBC/PKCS5Padding";
	}

	protected int getKeyIter() {
		return (int) Math.pow(2, 8);
	}

	protected int getKeySize() {
		return 256;
	}

	protected int getRandomPadSize() {
		return 11;
	}

	protected String encryptSession(SecuritySession securitySession) throws Exception {
		String serializedSession = serializeSession(securitySession);
		int randomPadSize = getRandomPadSize();
		byte[] decBytes = serializedSession.getBytes(StandardCharsets.UTF_8);
		byte[] randomBytes = new byte[randomPadSize];
		new SecureRandom().nextBytes(randomBytes);
		byte[] allBytes = Arrays.copyOf(randomBytes, randomPadSize + decBytes.length);
		System.arraycopy(decBytes, 0, allBytes, randomBytes.length, decBytes.length);
		byte[] encBytes = encCipher.doFinal(allBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(encBytes);
	}

	protected SecuritySession decryptSession(String encryptedSession) throws Exception {
		int randomPadSize = getRandomPadSize();
		byte[] encBytes = Base64.getUrlDecoder().decode(encryptedSession);
		byte[] decBytes = decCipher.doFinal(encBytes);
		return deserializeSession(new String(decBytes, randomPadSize, decBytes.length - randomPadSize, StandardCharsets.UTF_8));
	}

	private SecretKey generateKey(char[] pass, byte[] salt, int iterations, int size) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA" + size);
		KeySpec spec = new PBEKeySpec(pass, salt, iterations, size);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}
}
