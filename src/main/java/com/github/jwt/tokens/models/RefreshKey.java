package com.github.jwt.tokens.models;

import java.util.Objects;

public class RefreshKey {

    private String id;

    private int expirationTime;

    private String key;

    private String cookieName;

    public RefreshKey() {
    }

    public RefreshKey(String id, int expirationTime,
                      String key, String cookieName) {
        this.id = id;
        this.expirationTime = expirationTime;
        this.key = key;
        this.cookieName = cookieName;
    }

    public String getId() {
        return id;
    }

    public int getExpirationTime() {
        return expirationTime;
    }

    public String getKey() {
        return key;
    }

    public String getCookieName() {
        return cookieName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RefreshKey that = (RefreshKey) o;
        return expirationTime == that.expirationTime &&
                Objects.equals(id, that.id) &&
                Objects.equals(key, that.key) &&
                Objects.equals(cookieName, that.cookieName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, expirationTime, key, cookieName);
    }

    @Override
    public String toString() {
        return "RefreshKey{" +
                "id='" + id + '\'' +
                ", expirationTime=" + expirationTime +
                ", key='" + key + '\'' +
                ", cookieName='" + cookieName + '\'' +
                '}';
    }

}
