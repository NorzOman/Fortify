package com.facebook.imagepipeline.memory;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: BitmapCounterProvider.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u0012H\u0007J\b\u0010\u0013\u001a\u00020\u000bH\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000R\u0010\u0010\u0007\u001a\u00020\b8\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\n\u001a\u0004\u0018\u00010\u000bX\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\f\u001a\u00020\b8BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\r\u0010\u000e¨\u0006\u0014"}, d2 = {"Lcom/facebook/imagepipeline/memory/BitmapCounterProvider;", "", "<init>", "()V", "KB", "", "MB", "MAX_BITMAP_TOTAL_SIZE", "", "maxBitmapCount", "bitmapCounter", "Lcom/facebook/imagepipeline/memory/BitmapCounter;", "maxSizeHardCap", "getMaxSizeHardCap", "()I", "initialize", "", "bitmapCounterConfig", "Lcom/facebook/imagepipeline/memory/BitmapCounterConfig;", "get", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BitmapCounterProvider {
    public static final BitmapCounterProvider INSTANCE;
    private static final long KB = 1024;
    public static final int MAX_BITMAP_TOTAL_SIZE;
    private static final long MB = 1048576;
    private static volatile BitmapCounter bitmapCounter;
    private static int maxBitmapCount;

    private BitmapCounterProvider() {
    }

    static {
        BitmapCounterProvider bitmapCounterProvider = new BitmapCounterProvider();
        INSTANCE = bitmapCounterProvider;
        MAX_BITMAP_TOTAL_SIZE = bitmapCounterProvider.getMaxSizeHardCap();
        maxBitmapCount = BitmapCounterConfig.DEFAULT_MAX_BITMAP_COUNT;
    }

    private final int getMaxSizeHardCap() {
        int iMin = (int) Math.min(Runtime.getRuntime().maxMemory(), 2147483647L);
        if (iMin > 16777216) {
            return (iMin / 4) * 3;
        }
        return iMin / 2;
    }

    @JvmStatic
    public static final void initialize(BitmapCounterConfig bitmapCounterConfig) {
        Intrinsics.checkNotNullParameter(bitmapCounterConfig, "bitmapCounterConfig");
        if (bitmapCounter != null) {
            throw new IllegalStateException("BitmapCounter has already been created! `BitmapCounterProvider.initialize(...)` should only be called before `BitmapCounterProvider.get()` or not at all!".toString());
        }
        maxBitmapCount = bitmapCounterConfig.getMaxBitmapCount();
    }

    @JvmStatic
    public static final BitmapCounter get() {
        if (bitmapCounter == null) {
            synchronized (BitmapCounterProvider.class) {
                if (bitmapCounter == null) {
                    bitmapCounter = new BitmapCounter(maxBitmapCount, MAX_BITMAP_TOTAL_SIZE);
                }
                Unit unit = Unit.INSTANCE;
            }
        }
        BitmapCounter bitmapCounter2 = bitmapCounter;
        Intrinsics.checkNotNull(bitmapCounter2);
        return bitmapCounter2;
    }
}
