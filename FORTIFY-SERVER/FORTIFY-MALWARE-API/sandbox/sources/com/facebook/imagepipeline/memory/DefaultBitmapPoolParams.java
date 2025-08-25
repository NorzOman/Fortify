package com.facebook.imagepipeline.memory;

import android.util.SparseIntArray;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: DefaultBitmapPoolParams.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\u000b\u001a\u00020\fH\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u0014\u0010\u0006\u001a\u00020\u00058BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u000e\u0010\t\u001a\u00020\nX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\r"}, d2 = {"Lcom/facebook/imagepipeline/memory/DefaultBitmapPoolParams;", "", "<init>", "()V", "MAX_SIZE_SOFT_CAP", "", "maxSizeHardCap", "getMaxSizeHardCap", "()I", "DEFAULT_BUCKETS", "Landroid/util/SparseIntArray;", "get", "Lcom/facebook/imagepipeline/memory/PoolParams;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DefaultBitmapPoolParams {
    private static final int MAX_SIZE_SOFT_CAP = 0;
    public static final DefaultBitmapPoolParams INSTANCE = new DefaultBitmapPoolParams();
    private static final SparseIntArray DEFAULT_BUCKETS = new SparseIntArray(0);

    private DefaultBitmapPoolParams() {
    }

    private final int getMaxSizeHardCap() {
        int iMin = (int) Math.min(Runtime.getRuntime().maxMemory(), 2147483647L);
        if (iMin > 16777216) {
            return (iMin / 4) * 3;
        }
        return iMin / 2;
    }

    @JvmStatic
    public static final PoolParams get() {
        return new PoolParams(0, INSTANCE.getMaxSizeHardCap(), DEFAULT_BUCKETS);
    }
}
