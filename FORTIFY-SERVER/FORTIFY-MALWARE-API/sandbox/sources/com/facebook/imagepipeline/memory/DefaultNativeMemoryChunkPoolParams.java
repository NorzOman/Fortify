package com.facebook.imagepipeline.memory;

import android.util.SparseIntArray;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: DefaultNativeMemoryChunkPoolParams.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u0007\u001a\u00020\bH\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u0014\u0010\t\u001a\u00020\u00058BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\n\u0010\u000bR\u0014\u0010\f\u001a\u00020\u00058BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\r\u0010\u000b¨\u0006\u000e"}, d2 = {"Lcom/facebook/imagepipeline/memory/DefaultNativeMemoryChunkPoolParams;", "", "<init>", "()V", "SMALL_BUCKET_LENGTH", "", "LARGE_BUCKET_LENGTH", "get", "Lcom/facebook/imagepipeline/memory/PoolParams;", "maxSizeSoftCap", "getMaxSizeSoftCap", "()I", "maxSizeHardCap", "getMaxSizeHardCap", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DefaultNativeMemoryChunkPoolParams {
    public static final DefaultNativeMemoryChunkPoolParams INSTANCE = new DefaultNativeMemoryChunkPoolParams();
    private static final int LARGE_BUCKET_LENGTH = 2;
    private static final int SMALL_BUCKET_LENGTH = 5;

    private DefaultNativeMemoryChunkPoolParams() {
    }

    @JvmStatic
    public static final PoolParams get() {
        SparseIntArray sparseIntArray = new SparseIntArray();
        sparseIntArray.put(1024, 5);
        sparseIntArray.put(2048, 5);
        sparseIntArray.put(4096, 5);
        sparseIntArray.put(8192, 5);
        sparseIntArray.put(16384, 5);
        sparseIntArray.put(32768, 5);
        sparseIntArray.put(65536, 5);
        sparseIntArray.put(131072, 5);
        sparseIntArray.put(262144, 2);
        sparseIntArray.put(524288, 2);
        sparseIntArray.put(1048576, 2);
        DefaultNativeMemoryChunkPoolParams defaultNativeMemoryChunkPoolParams = INSTANCE;
        return new PoolParams(defaultNativeMemoryChunkPoolParams.getMaxSizeSoftCap(), defaultNativeMemoryChunkPoolParams.getMaxSizeHardCap(), sparseIntArray);
    }

    private final int getMaxSizeSoftCap() {
        int iMin = (int) Math.min(Runtime.getRuntime().maxMemory(), 2147483647L);
        if (iMin < 16777216) {
            return 3145728;
        }
        return iMin < 33554432 ? 6291456 : 12582912;
    }

    private final int getMaxSizeHardCap() {
        int iMin = (int) Math.min(Runtime.getRuntime().maxMemory(), 2147483647L);
        if (iMin < 16777216) {
            return iMin / 2;
        }
        return (iMin / 4) * 3;
    }
}
