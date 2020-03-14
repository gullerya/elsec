package com.gullerya.elsec.impl;

import com.gullerya.elsec.api.SecuritySession;
import com.gullerya.elsec.api.SessionsManager;
import org.junit.Assert;
import org.junit.Test;

public class EDSessionsManagerTest {

	@Test
	public void testSerialization() throws Exception {
		SecuritySession s = new SecuritySessionImpl(20, 40);
		SessionsManager sm = new EDSessionsManagerImpl(new SecurityConfigurationDefault());

		String sers = sm.serializeSession(s);
		Assert.assertNotNull(sers);
		Assert.assertFalse(sers.isEmpty());
		SecuritySession dess = sm.deserializeSession(sers);
		Assert.assertNotNull(dess);
		Assert.assertEquals(s.getUserId(), dess.getUserId());
		Assert.assertEquals(s.getRoles(), dess.getRoles());
	}

	@Test
	public void testEncryptionBasic() throws Exception {
		SecuritySession s = new SecuritySessionImpl(20, 40);
		EDSessionsManagerImpl sm = new EDSessionsManagerImpl(new SecurityConfigurationDefault());

		String encs = sm.encryptSession(s);
		Assert.assertNotNull(encs);
		Assert.assertFalse(encs.isEmpty());
		SecuritySession decs = sm.decryptSession(encs);
		Assert.assertNotNull(decs);
		Assert.assertEquals(s.getUserId(), decs.getUserId());
		Assert.assertEquals(s.getRoles(), decs.getRoles());
	}

	@Test
	public void testEncryptionEntropy() throws Exception {
		SecuritySession s = new SecuritySessionImpl(20, 40);
		EDSessionsManagerImpl sm = new EDSessionsManagerImpl(new SecurityConfigurationDefault());

		String encsA = sm.encryptSession(s);
		String encsB = sm.encryptSession(s);
		Assert.assertNotNull(encsA);
		Assert.assertFalse(encsA.isEmpty());
		Assert.assertNotNull(encsB);
		Assert.assertFalse(encsB.isEmpty());
		Assert.assertNotEquals(encsA, encsB);

		SecuritySession decsA = sm.decryptSession(encsA);
		Assert.assertNotNull(decsA);
		Assert.assertEquals(s.getUserId(), decsA.getUserId());
		Assert.assertEquals(s.getRoles(), decsA.getRoles());

		SecuritySession decsB = sm.decryptSession(encsB);
		Assert.assertNotNull(decsB);
		Assert.assertEquals(s.getUserId(), decsB.getUserId());
		Assert.assertEquals(s.getRoles(), decsB.getRoles());
	}
}
