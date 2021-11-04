package com.github.jwt.tokens.models;

import java.util.Objects;

public class AccessKey {

    private String id;

    private int expirationTime;

    private String key;

    private String optionalHeader;

    private String optionalCookie;

    public AccessKey() {
    }

    public AccessKey(String id,
                     int expirationTime,
                     String key,
                     String optionalHeader,
                     String optionalCookie) {
        this.id = id;
        this.expirationTime = expirationTime;
        this.key = key;
        this.optionalHeader = optionalHeader;
        this.optionalCookie = optionalCookie;
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

    public String getOptionalHeader() {
        return optionalHeader;
    }

    public String getOptionalCookie() {
        return optionalCookie;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AccessKey accessKey = (AccessKey) o;
        return expirationTime == accessKey.expirationTime &&
                Objects.equals(id, accessKey.id) &&
                Objects.equals(key, accessKey.key) &&
                Objects.equals(optionalHeader, accessKey.optionalHeader) &&
                Objects.equals(optionalCookie, accessKey.optionalCookie);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, expirationTime, key, optionalHeader, optionalCookie);
    }

    @Override
    public String toString() {
        return "AccessKey{" +
                "id='" + id + '\'' +
                ", expirationTime=" + expirationTime +
                ", key='" + key + '\'' +
                ", optionalHeader='" + optionalHeader + '\'' +
                ", optionalCookie='" + optionalCookie + '\'' +
                '}';
    }
}
