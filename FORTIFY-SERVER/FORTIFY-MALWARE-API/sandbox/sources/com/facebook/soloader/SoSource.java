package com.facebook.soloader;

import android.os.StrictMode;
import java.io.File;
import java.io.IOException;
import java.util.Collection;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public abstract class SoSource {
    public static final int LOAD_FLAG_ALLOW_IMPLICIT_PROVISION = 1;

    @Deprecated
    public static final int LOAD_FLAG_ALLOW_SOURCE_CHANGE = 2;
    public static final int LOAD_FLAG_MIN_CUSTOM_FLAG = 4;
    public static final int LOAD_RESULT_IMPLICITLY_PROVIDED = 2;
    public static final int LOAD_RESULT_LOADED = 1;
    public static final int LOAD_RESULT_NOT_FOUND = 0;
    public static final int PREPARE_FLAG_ALLOW_ASYNC_INIT = 1;
    public static final int PREPARE_FLAG_DISABLE_FS_SYNC_JOB = 4;
    public static final int PREPARE_FLAG_FORCE_REFRESH = 2;
    public static final int PREPARE_FLAG_SKIP_BACKUP_SO_SOURCE = 8;

    public void addToLdLibraryPath(Collection<String> collection) {
    }

    @Nullable
    public String[] getLibraryDependencies(String str) throws IOException {
        return null;
    }

    @Nullable
    public String getLibraryPath(String str) throws IOException {
        return null;
    }

    public abstract String getName();

    @Nullable
    protected File getSoFileByName(String str) throws IOException {
        return null;
    }

    public abstract int loadLibrary(String str, int i, StrictMode.ThreadPolicy threadPolicy) throws IOException;

    protected void prepare(int i) throws IOException {
    }

    @Nullable
    public abstract File unpackLibrary(String str) throws IOException;

    public String[] getSoSourceAbis() {
        return SysUtil.getSupportedAbis();
    }

    public String toString() {
        return getName();
    }
}
