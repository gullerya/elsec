package com.isure.security.api;

//  there might be up to 63 user roles (as the number of available bits in LONG/BIGINT)
//  the power argument MUST NOT exceed 62 (as of now reserved for ADMIN) since it will break the logic due to signed/unsigned effect
public enum UserRole {
	ANY(null),
	SAVER(0),
	EMPLOYER(1),
	DISTRIBUTOR(2),
	MANUFACTURER(3),

	DEMO_SAVER(20),

	SAFE_AGENT(61),
	ADMIN(62);

	private final long value;

	UserRole(Integer power) {
		this.value = power == null ? 0 : (long) Math.pow(2, power);
	}

	public long getValue() {
		return value;
	}

	public static UserRole fromValue(long value) {
		for (UserRole ur : values()) {
			if (ur.value == value) {
				return ur;
			}
		}
		throw new IllegalArgumentException("invalid value for UserRole (" + value + ")");
	}
}
