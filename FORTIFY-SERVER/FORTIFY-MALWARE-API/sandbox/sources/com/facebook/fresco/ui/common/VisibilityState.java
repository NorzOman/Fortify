package com.facebook.fresco.ui.common;

import kotlin.Metadata;
import kotlin.enums.EnumEntries;
import kotlin.enums.EnumEntriesKt;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* compiled from: VisibilityState.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\b\n\u0002\b\t\b\u0086\u0081\u0002\u0018\u0000 \u000b2\b\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\u000bB\u0011\b\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007j\u0002\b\bj\u0002\b\tj\u0002\b\n¨\u0006\f"}, d2 = {"Lcom/facebook/fresco/ui/common/VisibilityState;", "", "value", "", "<init>", "(Ljava/lang/String;II)V", "getValue", "()I", "UNKNOWN", "VISIBLE", "INVISIBLE", "Companion", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class VisibilityState {
    private static final /* synthetic */ EnumEntries $ENTRIES;
    private static final /* synthetic */ VisibilityState[] $VALUES;

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE;
    private static final VisibilityState[] VALUES;
    private final int value;
    public static final VisibilityState UNKNOWN = new VisibilityState("UNKNOWN", 0, -1);
    public static final VisibilityState VISIBLE = new VisibilityState("VISIBLE", 1, 1);
    public static final VisibilityState INVISIBLE = new VisibilityState("INVISIBLE", 2, 2);

    private static final /* synthetic */ VisibilityState[] $values() {
        return new VisibilityState[]{UNKNOWN, VISIBLE, INVISIBLE};
    }

    public static EnumEntries<VisibilityState> getEntries() {
        return $ENTRIES;
    }

    private VisibilityState(String str, int i, int i2) {
        this.value = i2;
    }

    public final int getValue() {
        return this.value;
    }

    static {
        VisibilityState[] visibilityStateArr$values = $values();
        $VALUES = visibilityStateArr$values;
        $ENTRIES = EnumEntriesKt.enumEntries(visibilityStateArr$values);
        INSTANCE = new Companion(null);
        VALUES = values();
    }

    /* compiled from: VisibilityState.kt */
    @Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\b\u001a\u0004\u0018\u00010\u00062\u0006\u0010\t\u001a\u00020\nR\u0016\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005X\u0082\u0004¢\u0006\u0004\n\u0002\u0010\u0007¨\u0006\u000b"}, d2 = {"Lcom/facebook/fresco/ui/common/VisibilityState$Companion;", "", "<init>", "()V", "VALUES", "", "Lcom/facebook/fresco/ui/common/VisibilityState;", "[Lcom/facebook/fresco/ui/common/VisibilityState;", "fromInt", "value", "", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final VisibilityState fromInt(int value) {
            for (VisibilityState visibilityState : VisibilityState.VALUES) {
                if (visibilityState.getValue() == value) {
                    return visibilityState;
                }
            }
            return null;
        }
    }

    public static VisibilityState valueOf(String str) {
        return (VisibilityState) Enum.valueOf(VisibilityState.class, str);
    }

    public static VisibilityState[] values() {
        return (VisibilityState[]) $VALUES.clone();
    }
}
