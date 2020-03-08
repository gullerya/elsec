package com.isure.security;

import com.isure.security.api.UserRole;
import org.junit.Assert;
import org.junit.Test;

public class RolesTest {

	@Test
	public void testA() {
		UserRole role = UserRole.ANY;
		Assert.assertEquals(0, role.getValue());
	}

	@Test
	public void testSaver() {
		UserRole role = UserRole.SAVER;
		ISureSecurityContext context = new ISureSecurityContextImpl(0, role.getValue());
		Assert.assertTrue(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
		Assert.assertFalse(context.isUserInRole(UserRole.ADMIN));
	}

	@Test
	public void testEmployer() {
		UserRole role = UserRole.EMPLOYER;
		ISureSecurityContext context = new ISureSecurityContextImpl(0, role.getValue());
		Assert.assertTrue(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
		Assert.assertFalse(context.isUserInRole(UserRole.ADMIN));
	}

	@Test
	public void testDistributor() {
		UserRole role = UserRole.DISTRIBUTOR;
		ISureSecurityContext context = new ISureSecurityContextImpl(0, role.getValue());
		Assert.assertTrue(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
		Assert.assertFalse(context.isUserInRole(UserRole.ADMIN));
	}

	@Test
	public void testManufacturer() {
		UserRole role = UserRole.MANUFACTURER;
		ISureSecurityContext context = new ISureSecurityContextImpl(0, role.getValue());
		Assert.assertTrue(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
		Assert.assertFalse(context.isUserInRole(UserRole.ADMIN));
	}

	@Test
	public void testSafeAgent() {
		UserRole role = UserRole.SAFE_AGENT;
		ISureSecurityContext context = new ISureSecurityContextImpl(0, role.getValue());
		Assert.assertTrue(context.isUserInRole(UserRole.SAFE_AGENT));
		Assert.assertFalse(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.ADMIN));
	}

	@Test
	public void testAdmin() {
		UserRole role = UserRole.ADMIN;
		ISureSecurityContext context = new ISureSecurityContextImpl(0, role.getValue());
		Assert.assertTrue(context.isUserInRole(UserRole.ADMIN));
		Assert.assertFalse(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
	}

	@Test
	public void testSaverDistributor() {
		long roleValue = UserRole.SAVER.getValue() + UserRole.DISTRIBUTOR.getValue();
		ISureSecurityContext context = new ISureSecurityContextImpl(0, roleValue);
		Assert.assertTrue(context.isUserInRole(UserRole.SAVER));
		Assert.assertTrue(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
		Assert.assertFalse(context.isUserInRole(UserRole.ADMIN));
	}

	@Test
	public void testSaverManufacturer() {
		long roleValue = UserRole.SAVER.getValue() + UserRole.MANUFACTURER.getValue();
		ISureSecurityContext context = new ISureSecurityContextImpl(0, roleValue);
		Assert.assertTrue(context.isUserInRole(UserRole.SAVER));
		Assert.assertTrue(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
		Assert.assertFalse(context.isUserInRole(UserRole.ADMIN));
	}

	@Test
	public void testSaverAdmin() {
		long roleValue = UserRole.SAVER.getValue() + UserRole.ADMIN.getValue();
		ISureSecurityContext context = new ISureSecurityContextImpl(0, roleValue);
		Assert.assertTrue(context.isUserInRole(UserRole.SAVER));
		Assert.assertTrue(context.isUserInRole(UserRole.ADMIN));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
	}


	@Test
	public void testDistributorAdmin() {
		long roleValue = UserRole.DISTRIBUTOR.getValue() + UserRole.ADMIN.getValue();
		ISureSecurityContext context = new ISureSecurityContextImpl(0, roleValue);
		Assert.assertTrue(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertTrue(context.isUserInRole(UserRole.ADMIN));
		Assert.assertFalse(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
	}

	@Test
	public void testEmployerDistributorAdmin() {
		long roleValue = UserRole.EMPLOYER.getValue() + UserRole.DISTRIBUTOR.getValue() + UserRole.ADMIN.getValue();
		ISureSecurityContext context = new ISureSecurityContextImpl(0, roleValue);
		Assert.assertTrue(context.isUserInRole(UserRole.EMPLOYER));
		Assert.assertTrue(context.isUserInRole(UserRole.DISTRIBUTOR));
		Assert.assertTrue(context.isUserInRole(UserRole.ADMIN));
		Assert.assertFalse(context.isUserInRole(UserRole.SAVER));
		Assert.assertFalse(context.isUserInRole(UserRole.MANUFACTURER));
		Assert.assertFalse(context.isUserInRole(UserRole.SAFE_AGENT));
	}
}
