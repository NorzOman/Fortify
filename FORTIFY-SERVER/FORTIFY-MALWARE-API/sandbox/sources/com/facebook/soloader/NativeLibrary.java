package com.facebook.soloader;

import java.util.Iterator;
import java.util.List;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public abstract class NativeLibrary {
    private static final String TAG = "com.facebook.soloader.NativeLibrary";

    @Nullable
    private List<String> mLibraryNames;
    private final Object mLock = new Object();
    private Boolean mLoadLibraries = true;
    private boolean mLibrariesLoaded = false;

    @Nullable
    private volatile UnsatisfiedLinkError mLinkError = null;

    protected void initialNativeCheck() throws UnsatisfiedLinkError {
    }

    protected NativeLibrary(List<String> list) {
        this.mLibraryNames = list;
    }

    @Nullable
    public boolean loadLibraries() {
        synchronized (this.mLock) {
            if (!this.mLoadLibraries.booleanValue()) {
                return this.mLibrariesLoaded;
            }
            try {
                try {
                    List<String> list = this.mLibraryNames;
                    if (list != null) {
                        Iterator<String> it = list.iterator();
                        while (it.hasNext()) {
                            SoLoader.loadLibrary(it.next());
                        }
                    }
                    initialNativeCheck();
                    this.mLibrariesLoaded = true;
                    this.mLibraryNames = null;
                } catch (Throwable th) {
                    LogUtil.e(TAG, "Failed to load native lib (other error): ", th);
                    this.mLinkError = new UnsatisfiedLinkError("Failed loading libraries");
                    this.mLinkError.initCause(th);
                    this.mLibrariesLoaded = false;
                }
            } catch (UnsatisfiedLinkError e) {
                LogUtil.e(TAG, "Failed to load native lib (initial check): ", e);
                this.mLinkError = e;
                this.mLibrariesLoaded = false;
            }
            this.mLoadLibraries = false;
            return this.mLibrariesLoaded;
        }
    }

    public void ensureLoaded() throws UnsatisfiedLinkError {
        if (!loadLibraries()) {
            throw this.mLinkError;
        }
    }

    @Nullable
    public UnsatisfiedLinkError getError() {
        return this.mLinkError;
    }
}
