package com.facebook.common.references;

import com.facebook.common.internal.Objects;
import com.facebook.common.internal.Preconditions;
import com.facebook.common.logging.FLog;
import java.util.IdentityHashMap;
import java.util.Map;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class SharedReference<T> {
    private static final Map<Object, Integer> sLiveObjects = new IdentityHashMap();
    private int mRefCount;

    @Nullable
    private final ResourceReleaser<T> mResourceReleaser;

    @Nullable
    private T mValue;

    public SharedReference(T t, @Nullable ResourceReleaser<T> resourceReleaser, boolean z) {
        this.mValue = (T) Preconditions.checkNotNull(t);
        this.mResourceReleaser = resourceReleaser;
        this.mRefCount = 1;
        if (z) {
            addLiveReference(t);
        }
    }

    public SharedReference(T t, ResourceReleaser<T> resourceReleaser) {
        this(t, resourceReleaser, false);
    }

    private static void addLiveReference(Object obj) {
        Map<Object, Integer> map = sLiveObjects;
        synchronized (map) {
            Integer num = map.get(obj);
            if (num == null) {
                map.put(obj, 1);
            } else {
                map.put(obj, Integer.valueOf(num.intValue() + 1));
            }
        }
    }

    private static void removeLiveReference(Object obj) {
        Map<Object, Integer> map = sLiveObjects;
        synchronized (map) {
            Integer num = map.get(obj);
            if (num == null) {
                FLog.wtf("SharedReference", "No entry in sLiveObjects for value of type %s", obj.getClass());
            } else if (num.intValue() == 1) {
                map.remove(obj);
            } else {
                map.put(obj, Integer.valueOf(num.intValue() - 1));
            }
        }
    }

    @Nullable
    public synchronized T get() {
        return this.mValue;
    }

    public synchronized boolean isValid() {
        return this.mRefCount > 0;
    }

    public static boolean isValid(@Nullable SharedReference<?> sharedReference) {
        return sharedReference != null && sharedReference.isValid();
    }

    public synchronized void addReference() {
        ensureValid();
        this.mRefCount++;
    }

    public synchronized boolean addReferenceIfValid() {
        if (!isValid()) {
            return false;
        }
        addReference();
        return true;
    }

    public synchronized boolean deleteReferenceIfValid() {
        if (!isValid()) {
            return false;
        }
        deleteReference();
        return true;
    }

    public void deleteReference() {
        T t;
        if (decreaseRefCount() == 0) {
            synchronized (this) {
                t = this.mValue;
                this.mValue = null;
            }
            if (t != null) {
                ResourceReleaser<T> resourceReleaser = this.mResourceReleaser;
                if (resourceReleaser != null) {
                    resourceReleaser.release(t);
                }
                removeLiveReference(t);
            }
        }
    }

    private synchronized int decreaseRefCount() {
        int i;
        ensureValid();
        Preconditions.checkArgument(Boolean.valueOf(this.mRefCount > 0));
        i = this.mRefCount - 1;
        this.mRefCount = i;
        return i;
    }

    private void ensureValid() {
        if (!isValid(this)) {
            throw new NullReferenceException();
        }
    }

    public synchronized int getRefCountTestOnly() {
        return this.mRefCount;
    }

    public static class NullReferenceException extends RuntimeException {
        public NullReferenceException() {
            super("Null shared reference");
        }
    }

    public static String reportData() {
        return Objects.toStringHelper("SharedReference").add("live_objects_count", sLiveObjects.size()).toString();
    }
}
