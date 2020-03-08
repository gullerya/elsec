package com.isure.security;

import com.isure.security.api.SecurityService;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
final class SecurityServiceImpl implements SecurityService {
	private static final Logger logger = LoggerFactory.getLogger(SecurityServiceImpl.class);
	private static final int DEFAULT_TOKEN_TTL = 12 * 60 * 1000;

	private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
	private final CompletableFuture<SecretKey> authTokenSecretKey = new CompletableFuture<>();

	static final String SECURITY_CONTEXT_KEY = "isure.security.context";

	@PostConstruct
	private void init() throws Exception {
		//  allowing AES256
		Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
		field.setAccessible(true);
		Field modifiersField = Field.class.getDeclaredField("modifiers");
		modifiersField.setAccessible(true);
		modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
		field.set(null, false);
		modifiersField.setInt(field, field.getModifiers() & Modifier.FINAL);
		modifiersField.setAccessible(false);

		//  init own keys
		initCyphers();

		//  inject self into the servlet endpoints
		AuthenticationFilter.setSecurityService(this);
	}

	@Override
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

	@Override
	public SecretKey generateKey(String pass, String salt) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 11536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}

	@Override
	public Cookie createCookie(long userId, long roles) {
		return createCookie(new ISurePrincipal(userId, roles));
	}

	@Override
	public byte[] encrypt(String input, SecretKey key) throws Exception {
		//  prepare cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		AlgorithmParameters params = cipher.getParameters();

		//  process data
		byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		byte[] encBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
		byte[] finalBytes = new byte[16 + encBytes.length];
		System.arraycopy(iv, 0, finalBytes, 0, 16);
		System.arraycopy(encBytes, 0, finalBytes, 16, encBytes.length);
		return finalBytes;
	}

	@Override
	public String decrypt(byte[] input, SecretKey key) throws Exception {
		//  process data
		byte[] encBytes = new byte[input.length - 16];
		byte[] iv = new byte[16];
		System.arraycopy(input, 0, iv, 0, 16);
		System.arraycopy(input, 16, encBytes, 0, encBytes.length);

		//  prepare cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec ips = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, key, ips);

		return new String(cipher.doFinal(encBytes), StandardCharsets.UTF_8);
	}

	@Override
	public String hashPass(String pass) {
		return argon2.hash(7, 65536, 4, pass.getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public boolean verifyPass(String candidate, String hash) {
		return argon2.verify(hash, candidate.getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public ISureSecurityContext getRequestSecurityContext(HttpServletRequest request) {
		ISureSecurityContext result = null;
		if (request.getAttribute(SecurityServiceImpl.SECURITY_CONTEXT_KEY) != null) {
			//  security context already set - use it
			result = (ISureSecurityContext) request.getAttribute(SecurityServiceImpl.SECURITY_CONTEXT_KEY);
		} else {
			//  security context has not yet been set - try to extract it from the cookie
			String cookie = SecurityUtils.retrieveSecurityCookie(request.getCookies());
			if (cookie != null && !cookie.isEmpty()) {
				SecurityServiceImpl.ISurePrincipal token = extractSecurityToken(cookie);
				if (token != null) {
					result = new ISureSecurityContextImpl(token.userId, token.userRoles);
				}
			}
		}

		return result;
	}

	@Override
	public long getRequestUserId(HttpServletRequest request) {
		ISureSecurityContext sContext = getRequestSecurityContext(request);

		if (sContext == null) {
			throw new IllegalStateException("security context missing");
		} else {
			return sContext.getUserId();
		}
	}

	Cookie createCookie(ISurePrincipal token) {
		if (token == null) {
			throw new IllegalArgumentException("principal data MUST NOT be null");
		}

		Cookie result;
		try {
			String tokenAsText = token.toString();
			byte[] eBytes = encrypt(tokenAsText, authTokenSecretKey.get());
			String encToken = Base64.getUrlEncoder().withoutPadding().encodeToString(eBytes);
			result = new Cookie(SECURITY_COOKIE_NAME, encToken);
			result.setDomain("");
			result.setPath("/");
			result.setMaxAge(DEFAULT_TOKEN_TTL / 1000 * 2);
			result.setSecure(false);
			result.setHttpOnly(true);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return result;
	}

	ISurePrincipal extractSecurityToken(String encToken) {
		ISurePrincipal token = null;
		try {
			String tokenAsText = decrypt(Base64.getUrlDecoder().decode(encToken), authTokenSecretKey.get());
			token = new ISurePrincipal(tokenAsText);
		} catch (Exception e) {
			logger.error("failed to decrypt '" + encToken + "'");
		}
		return token;
	}

	private void initCyphers() {
		ForkJoinPool.commonPool().execute(() -> {
			try {
				SecretKey key = generateKey("Pull me under I'm not afraid", "Seventh son of the seventh son");
				authTokenSecretKey.complete(key);
				logger.info("com.isure.security essentials set up successfully");
			} catch (Throwable t) {
				logger.error("failed to initialize com.isure.security essentials", t);
				authTokenSecretKey.completeExceptionally(t);
			}
		});
	}

	final static class ISurePrincipal {
		private static final String TOKEN_ITEMS_SEPARATOR = "#";
		long userId;
		long userRoles;
		long expirationTime;

		private ISurePrincipal(long userId, long userRoles) {
			this.userId = userId;
			this.userRoles = userRoles;
			this.expirationTime = System.currentTimeMillis() + DEFAULT_TOKEN_TTL;
		}

		private ISurePrincipal(String serialized) {
			String[] parts = serialized.split(TOKEN_ITEMS_SEPARATOR);
			userId = Long.parseLong(parts[0]);
			userRoles = Long.parseLong(parts[1]);
			expirationTime = Long.parseLong(parts[2]);
		}

		boolean isExpired() {
			return System.currentTimeMillis() > expirationTime;
		}

		ISurePrincipal renewIfRelevant() {
			ISurePrincipal result = null;
			if (expirationTime > System.currentTimeMillis() && expirationTime - System.currentTimeMillis() < DEFAULT_TOKEN_TTL / 2) {
				result = new ISurePrincipal(userId, userRoles);
			}
			return result;
		}

		@Override
		public String toString() {
			return userId + TOKEN_ITEMS_SEPARATOR + userRoles + TOKEN_ITEMS_SEPARATOR + expirationTime;
		}
	}
}
