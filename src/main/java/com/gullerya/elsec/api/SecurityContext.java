package com.gullerya.elsec.api;

public interface SecurityContext {

    Long getUserId();

    Long getUserRoles();

    boolean isUserInRole(Long role);
}
