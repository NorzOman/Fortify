package com.facebook.imagepipeline.common;

import kotlin.Metadata;
import kotlin.enums.EnumEntries;
import kotlin.enums.EnumEntriesKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* compiled from: Priority.kt */
@Metadata(d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\b\u0007\b\u0086\u0081\u0002\u0018\u0000 \u00072\b\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\u0007B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003j\u0002\b\u0004j\u0002\b\u0005j\u0002\b\u0006¨\u0006\b"}, d2 = {"Lcom/facebook/imagepipeline/common/Priority;", "", "<init>", "(Ljava/lang/String;I)V", "LOW", "MEDIUM", "HIGH", "Companion", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class Priority {
    private static final /* synthetic */ EnumEntries $ENTRIES;
    private static final /* synthetic */ Priority[] $VALUES;

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE;
    public static final Priority LOW = new Priority("LOW", 0);
    public static final Priority MEDIUM = new Priority("MEDIUM", 1);
    public static final Priority HIGH = new Priority("HIGH", 2);

    private static final /* synthetic */ Priority[] $values() {
        return new Priority[]{LOW, MEDIUM, HIGH};
    }

    public static EnumEntries<Priority> getEntries() {
        return $ENTRIES;
    }

    @JvmStatic
    public static final Priority getHigherPriority(Priority priority, Priority priority2) {
        return INSTANCE.getHigherPriority(priority, priority2);
    }

    private Priority(String str, int i) {
    }

    static {
        Priority[] priorityArr$values = $values();
        $VALUES = priorityArr$values;
        $ENTRIES = EnumEntriesKt.enumEntries(priorityArr$values);
        INSTANCE = new Companion(null);
    }

    /* compiled from: Priority.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u0005H\u0007¨\u0006\b"}, d2 = {"Lcom/facebook/imagepipeline/common/Priority$Companion;", "", "<init>", "()V", "getHigherPriority", "Lcom/facebook/imagepipeline/common/Priority;", "priority1", "priority2", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final Priority getHigherPriority(Priority priority1, Priority priority2) {
            Intrinsics.checkNotNullParameter(priority1, "priority1");
            Intrinsics.checkNotNullParameter(priority2, "priority2");
            return priority1.ordinal() > priority2.ordinal() ? priority1 : priority2;
        }
    }

    public static Priority valueOf(String str) {
        return (Priority) Enum.valueOf(Priority.class, str);
    }

    public static Priority[] values() {
        return (Priority[]) $VALUES.clone();
    }
}
