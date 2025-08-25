package com.facebook.imagepipeline.core;

import kotlin.Metadata;
import kotlin.enums.EnumEntries;
import kotlin.enums.EnumEntriesKt;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* compiled from: DownsampleMode.kt */
@Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\b\u0006\b\u0086\u0081\u0002\u0018\u00002\b\u0012\u0004\u0012\u00020\u00000\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003j\u0002\b\u0004j\u0002\b\u0005j\u0002\b\u0006¨\u0006\u0007"}, d2 = {"Lcom/facebook/imagepipeline/core/DownsampleMode;", "", "<init>", "(Ljava/lang/String;I)V", "ALWAYS", "AUTO", "NEVER", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DownsampleMode {
    private static final /* synthetic */ EnumEntries $ENTRIES;
    private static final /* synthetic */ DownsampleMode[] $VALUES;
    public static final DownsampleMode ALWAYS = new DownsampleMode("ALWAYS", 0);
    public static final DownsampleMode AUTO = new DownsampleMode("AUTO", 1);
    public static final DownsampleMode NEVER = new DownsampleMode("NEVER", 2);

    private static final /* synthetic */ DownsampleMode[] $values() {
        return new DownsampleMode[]{ALWAYS, AUTO, NEVER};
    }

    public static EnumEntries<DownsampleMode> getEntries() {
        return $ENTRIES;
    }

    private DownsampleMode(String str, int i) {
    }

    static {
        DownsampleMode[] downsampleModeArr$values = $values();
        $VALUES = downsampleModeArr$values;
        $ENTRIES = EnumEntriesKt.enumEntries(downsampleModeArr$values);
    }

    public static DownsampleMode valueOf(String str) {
        return (DownsampleMode) Enum.valueOf(DownsampleMode.class, str);
    }

    public static DownsampleMode[] values() {
        return (DownsampleMode[]) $VALUES.clone();
    }
}
