package com.facebook.imagepipeline.memory;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* compiled from: BitmapCounterConfig.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0006\u0018\u0000 \b2\u00020\u0001:\u0001\bB\u0011\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\t"}, d2 = {"Lcom/facebook/imagepipeline/memory/BitmapCounterConfig;", "", "maxBitmapCount", "", "<init>", "(I)V", "getMaxBitmapCount", "()I", "Companion", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BitmapCounterConfig {
    public static final int DEFAULT_MAX_BITMAP_COUNT = 384;
    private final int maxBitmapCount;

    public BitmapCounterConfig() {
        this(0, 1, null);
    }

    public BitmapCounterConfig(int i) {
        this.maxBitmapCount = i;
    }

    public /* synthetic */ BitmapCounterConfig(int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? DEFAULT_MAX_BITMAP_COUNT : i);
    }

    public final int getMaxBitmapCount() {
        return this.maxBitmapCount;
    }
}
