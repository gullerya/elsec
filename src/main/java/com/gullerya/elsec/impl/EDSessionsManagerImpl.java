package com.gullerya.elsec.impl;

import com.gullerya.elsec.SecurityConfigurationSPI;
import com.gullerya.elsec.api.SecuritySession;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Encrypted Data strategy session management implementation
 */
class EDSessionsManagerImpl extends SessionsManagerBaseImpl {
	private final SecretKey edKey;

	EDSessionsManagerImpl(SecurityConfigurationSPI configurer) throws Exception {
		super(configurer);
		edKey = generateKey(configurer.getPass(), configurer.getSalt());
	}

	@Override
	public SecuritySession obtainSession(HttpServletRequest request) throws Exception {
		SecuritySession result = getSessionAttribute(request);
		if (result == null) {
			String ed = getSecurityCookieValue(request);
			if (ed != null && !ed.isEmpty()) {
				result = decryptSession(ed, edKey);
				if (result != null) {
					setSessionAttribute(request, result);
				}
			}
		}
		return result;
	}

	private String encryptSession(SecuritySession securitySession, SecretKey key) throws Exception {
		//  serialize
		String serializedSession = serializeSecuritySession(securitySession);

		//  prepare cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		AlgorithmParameters params = cipher.getParameters();

		//  process data
		byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		byte[] encBytes = cipher.doFinal(serializedSession.getBytes(StandardCharsets.UTF_8));
		byte[] finalBytes = new byte[16 + encBytes.length];
		System.arraycopy(iv, 0, finalBytes, 0, 16);
		System.arraycopy(encBytes, 0, finalBytes, 16, encBytes.length);

		//  encode to Base64
		return Base64.getEncoder().encodeToString(finalBytes);
	}

	private SecuritySession decryptSession(String ed, SecretKey key) throws Exception {
		//  decode from Base64
		byte[] input = Base64.getDecoder().decode(ed);

		//  process data
		byte[] encBytes = new byte[input.length - 16];
		byte[] iv = new byte[16];
		System.arraycopy(input, 0, iv, 0, 16);
		System.arraycopy(input, 16, encBytes, 0, encBytes.length);

		//  prepare cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec ips = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, key, ips);

		return deserializeSecuritySession(new String(cipher.doFinal(encBytes), StandardCharsets.UTF_8));
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

	public SecretKey generateKey() throws Exception {
		char[] passPhrase = new SecureRandom()
				.ints(32, 0, 65536)
				.boxed()
				.flatMap(i -> Stream.of(Character.toChars(i)))
				.map(String::valueOf)
				.collect(Collectors.joining())
				.toCharArray();

		byte[] salt = new byte[32];
		new SecureRandom().nextBytes(salt);

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		KeySpec spec = new PBEKeySpec(passPhrase, salt, 11536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}

	public SecretKey generateKey(String pass, String salt) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 11536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}
}
