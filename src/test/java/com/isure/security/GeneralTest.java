package com.isure.security;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import java.util.HashSet;
import java.util.Set;

@RunWith(SpringRunner.class)
@ContextConfiguration({
		"/spring/tests-context.xml"
})
public class GeneralTest {

	@Autowired
	private SecurityServiceImpl securityService;

	@Test
	public void testA() {
		Cookie cookie = securityService.createCookie(0, 1);
		Assert.assertNotNull(cookie);
	}

	@Test
	public void encryptDecryptRandomKey() throws Exception {
		SecretKey key1 = securityService.generateKey();
		SecretKey key2 = securityService.generateKey();

		String input = "some text to encrypt";

		byte[] crypto1 = securityService.encrypt(input, key1);
		byte[] crypto2 = securityService.encrypt(input, key2);

		Assert.assertNotEquals(crypto1, crypto2);

		String output1 = securityService.decrypt(crypto1, key1);
		String output2 = securityService.decrypt(crypto2, key2);

		Assert.assertEquals(input, output1);
		Assert.assertEquals(input, output2);
	}

	@Test
	public void encryptDecryptConstantKey() throws Exception {
		String pass = "constant pass";
		String salt = "constant salt";
		SecretKey key1 = securityService.generateKey(pass, salt);
		SecretKey key2 = securityService.generateKey(pass, salt);

		String input = "some text to encrypt";

		byte[] crypto1 = securityService.encrypt(input, key1);
		byte[] crypto2 = securityService.encrypt(input, key2);

		Assert.assertNotEquals(crypto1, crypto2);

		String output1 = securityService.decrypt(crypto1, key2);
		String output2 = securityService.decrypt(crypto2, key1);

		Assert.assertEquals(input, output1);
		Assert.assertEquals(input, output2);
	}
}
