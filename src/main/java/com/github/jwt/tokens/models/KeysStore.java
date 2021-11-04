package com.github.jwt.tokens.models;

import java.util.Objects;

public class KeysStore {

    private int priority;

    private AccessKey accessKey;

    private RefreshKey refreshKey;

    public KeysStore() {
    }

    public KeysStore(int priority, AccessKey accessKey, RefreshKey refreshKey) {
        this.priority = priority;
        this.accessKey = accessKey;
        this.refreshKey = refreshKey;
    }

    public int getPriority() {
        return priority;
    }

    public AccessKey getAccessKey() {
        return accessKey;
    }

    public RefreshKey getRefreshKey() {
        return refreshKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeysStore keysStore = (KeysStore) o;
        return priority == keysStore.priority &&
                Objects.equals(accessKey, keysStore.accessKey) &&
                Objects.equals(refreshKey, keysStore.refreshKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(priority, accessKey, refreshKey);
    }

    @Override
    public String toString() {
        return "KeysStore{" +
                "priority=" + priority +
                ", accessKey=" + accessKey +
                ", refreshKey=" + refreshKey +
                '}';
    }
}
