package com.facebook.common.statfs;

import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import com.facebook.common.internal.Throwables;
import java.io.File;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class StatFsHelper {
    public static final long DEFAULT_DISK_OLIVE_LEVEL_IN_BYTES = 1048576000;
    public static final long DEFAULT_DISK_RED_LEVEL_IN_BYTES = 104857600;
    public static final int DEFAULT_DISK_RED_LEVEL_IN_MB = 100;
    public static final long DEFAULT_DISK_YELLOW_LEVEL_IN_BYTES = 419430400;
    public static final int DEFAULT_DISK_YELLOW_LEVEL_IN_MB = 400;
    private static final long RESTAT_INTERVAL_MS = TimeUnit.MINUTES.toMillis(2);
    private static StatFsHelper sStatsFsHelper;

    @Nullable
    private volatile File mExternalPath;

    @Nullable
    private volatile File mInternalPath;
    private long mLastRestatTime;

    @Nullable
    private volatile StatFs mInternalStatFs = null;

    @Nullable
    private volatile StatFs mExternalStatFs = null;
    private volatile boolean mInitialized = false;
    private final Lock lock = new ReentrantLock();

    public enum StorageType {
        INTERNAL,
        EXTERNAL
    }

    public static synchronized StatFsHelper getInstance() {
        if (sStatsFsHelper == null) {
            sStatsFsHelper = new StatFsHelper();
        }
        return sStatsFsHelper;
    }

    protected StatFsHelper() {
    }

    private void ensureInitialized() {
        if (this.mInitialized) {
            return;
        }
        this.lock.lock();
        try {
            if (!this.mInitialized) {
                this.mInternalPath = Environment.getDataDirectory();
                this.mExternalPath = Environment.getExternalStorageDirectory();
                updateStats();
                this.mInitialized = true;
            }
        } finally {
            this.lock.unlock();
        }
    }

    public boolean testLowDiskSpace(StorageType storageType, long j) {
        ensureInitialized();
        long availableStorageSpace = getAvailableStorageSpace(storageType);
        return availableStorageSpace <= 0 || availableStorageSpace < j;
    }

    public long getFreeStorageSpace(StorageType storageType) {
        ensureInitialized();
        maybeUpdateStats();
        StatFs statFs = storageType == StorageType.INTERNAL ? this.mInternalStatFs : this.mExternalStatFs;
        if (statFs != null) {
            return statFs.getBlockSizeLong() * statFs.getFreeBlocksLong();
        }
        return -1L;
    }

    public long getTotalStorageSpace(StorageType storageType) {
        ensureInitialized();
        maybeUpdateStats();
        StatFs statFs = storageType == StorageType.INTERNAL ? this.mInternalStatFs : this.mExternalStatFs;
        if (statFs != null) {
            return statFs.getBlockSizeLong() * statFs.getBlockCountLong();
        }
        return -1L;
    }

    public long getAvailableStorageSpace(StorageType storageType) {
        ensureInitialized();
        maybeUpdateStats();
        StatFs statFs = storageType == StorageType.INTERNAL ? this.mInternalStatFs : this.mExternalStatFs;
        if (statFs != null) {
            return statFs.getBlockSizeLong() * statFs.getAvailableBlocksLong();
        }
        return 0L;
    }

    public boolean isLowSpaceCondition() {
        return getAvailableStorageSpace(StorageType.INTERNAL) < DEFAULT_DISK_YELLOW_LEVEL_IN_BYTES;
    }

    public boolean isVeryLowSpaceCondition() {
        return getAvailableStorageSpace(StorageType.INTERNAL) < DEFAULT_DISK_RED_LEVEL_IN_BYTES;
    }

    public boolean isHighSpaceCondition() {
        return getAvailableStorageSpace(StorageType.INTERNAL) > DEFAULT_DISK_OLIVE_LEVEL_IN_BYTES;
    }

    private void maybeUpdateStats() {
        if (this.lock.tryLock()) {
            try {
                if (SystemClock.uptimeMillis() - this.mLastRestatTime > RESTAT_INTERVAL_MS) {
                    updateStats();
                }
            } finally {
                this.lock.unlock();
            }
        }
    }

    public void resetStats() {
        if (this.lock.tryLock()) {
            try {
                ensureInitialized();
                updateStats();
            } finally {
                this.lock.unlock();
            }
        }
    }

    private void updateStats() {
        this.mInternalStatFs = updateStatsHelper(this.mInternalStatFs, this.mInternalPath);
        this.mExternalStatFs = updateStatsHelper(this.mExternalStatFs, this.mExternalPath);
        this.mLastRestatTime = SystemClock.uptimeMillis();
    }

    @Nullable
    private StatFs updateStatsHelper(@Nullable StatFs statFs, @Nullable File file) {
        StatFs statFs2 = null;
        if (file == null || !file.exists()) {
            return null;
        }
        try {
            if (statFs == null) {
                statFs = createStatFs(file.getAbsolutePath());
            } else {
                statFs.restat(file.getAbsolutePath());
            }
            statFs2 = statFs;
            return statFs2;
        } catch (IllegalArgumentException unused) {
            return statFs2;
        } catch (Throwable th) {
            throw Throwables.propagate(th);
        }
    }

    protected static StatFs createStatFs(String str) {
        return new StatFs(str);
    }
}
