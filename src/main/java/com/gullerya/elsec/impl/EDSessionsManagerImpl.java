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
import java.util.Base64;
import java.util.UUID;

/**
 * Encrypted Data strategy session management implementation
 */
class EDSessionsManagerImpl extends SessionsManagerBaseImpl {
	private static final Logger logger = LoggerFactory.getLogger(EDSessionsManagerImpl.class);
	private final String passPhrase;
	private final SecretKey key;

	EDSessionsManagerImpl(SecurityConfigurationSPI configurer) throws Exception {
		super(configurer);
		if (configurer.getPass() != null && !configurer.getPass().isEmpty()) {
			passPhrase = configurer.getPass();
		} else {
			logger.warn("ED session manager initialized with a RANDOM pass-phrase");
			passPhrase = UUID.randomUUID().toString();
		}

		byte[] salt = new byte[16];
		key = generateKey(getPassPhrase().toCharArray(), salt, getKeyIter(), getKeySize());
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
		byte[] rnd = new byte[randomPadSize];
		new SecureRandom().nextBytes(rnd);
		byte[] dec = serializedSession.getBytes(StandardCharsets.UTF_8);
		byte[] all = new byte[rnd.length + dec.length];
		System.arraycopy(rnd, 0, all, 0, rnd.length);
		System.arraycopy(dec, 0, all, rnd.length, dec.length);

		Cipher cipher = Cipher.getInstance(getCipherAlgo());
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] enc = cipher.doFinal(all);
		byte[] iv = cipher.getIV();

		byte[] fin = new byte[enc.length + iv.length];
		System.arraycopy(enc, 0, fin, 0, enc.length);
		System.arraycopy(iv, 0, fin, enc.length, iv.length);

		return Base64.getUrlEncoder().withoutPadding().encodeToString(fin);
	}

	protected SecuritySession decryptSession(String encryptedSession) throws Exception {
		int randomPadSize = getRandomPadSize();
		byte[] all = Base64.getUrlDecoder().decode(encryptedSession);

		IvParameterSpec ivSpec = new IvParameterSpec(all, all.length - 16, 16);
		Cipher cipher = Cipher.getInstance(getCipherAlgo());
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

		byte[] dec = cipher.doFinal(all, 0, all.length - 16);
		String serializedSession = new String(dec, randomPadSize, dec.length - randomPadSize, StandardCharsets.UTF_8);
		return deserializeSession(serializedSession);
	}

	private SecretKey generateKey(char[] pass, byte[] salt, int iterations, int size) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(pass, salt, iterations, size);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}
}
