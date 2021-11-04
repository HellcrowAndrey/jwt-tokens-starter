package com.github.jwt.tokens.models;

import java.util.Objects;

public class KeysInfo {

    private String role;

    private int priority;

    private int accessTokenExpireTime;

    private int refreshTokenExpireTime;

    private String accessTokenHeaderName;

    private String accessTokenCookieName;

    private String refreshTokenCookieName;

    public KeysInfo() {
    }

    public KeysInfo(String role,
                    int priority,
                    int accessTokenExpireTime,
                    int refreshTokenExpireTime) {
        this.role = role;
        this.priority = priority;
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.refreshTokenExpireTime = refreshTokenExpireTime;
        this.accessTokenHeaderName = "default";
        this.accessTokenCookieName = "access_token";
        this.refreshTokenCookieName = "refresh_token";
    }

    public KeysInfo(String role,
                    int priority,
                    int accessTokenExpireTime,
                    int refreshTokenExpireTime,
                    String accessTokenHeaderName,
                    String accessTokenCookieName,
                    String refreshTokenCookieName) {
        this.role = role;
        this.priority = priority;
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.refreshTokenExpireTime = refreshTokenExpireTime;
        this.accessTokenHeaderName = accessTokenHeaderName;
        this.accessTokenCookieName = accessTokenCookieName;
        this.refreshTokenCookieName = refreshTokenCookieName;
    }

    public String getRole() {
        return role;
    }

    public int getPriority() {
        return priority;
    }

    public int getAccessTokenExpireTime() {
        return accessTokenExpireTime;
    }

    public int getRefreshTokenExpireTime() {
        return refreshTokenExpireTime;
    }

    public String getAccessTokenHeaderName() {
        return accessTokenHeaderName;
    }

    public String getAccessTokenCookieName() {
        return accessTokenCookieName;
    }

    public String getRefreshTokenCookieName() {
        return refreshTokenCookieName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeysInfo keysInfo = (KeysInfo) o;
        return priority == keysInfo.priority &&
                accessTokenExpireTime == keysInfo.accessTokenExpireTime &&
                refreshTokenExpireTime == keysInfo.refreshTokenExpireTime &&
                Objects.equals(role, keysInfo.role) &&
                Objects.equals(accessTokenHeaderName, keysInfo.accessTokenHeaderName) &&
                Objects.equals(accessTokenCookieName, keysInfo.accessTokenCookieName) &&
                Objects.equals(refreshTokenCookieName, keysInfo.refreshTokenCookieName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                role, priority, accessTokenExpireTime, refreshTokenExpireTime,
                accessTokenHeaderName, accessTokenCookieName, refreshTokenCookieName
        );
    }

    @Override
    public String toString() {
        return "KeysInfo{" +
                "role='" + role + '\'' +
                ", priority=" + priority +
                ", accessTokenExpireTime=" + accessTokenExpireTime +
                ", refreshTokenExpireTime=" + refreshTokenExpireTime +
                ", accessTokenHeaderName='" + accessTokenHeaderName + '\'' +
                ", accessTokenCookieName='" + accessTokenCookieName + '\'' +
                ", refreshTokenCookieName='" + refreshTokenCookieName + '\'' +
                '}';
    }

}
