package com.facebook.yoga;

/* loaded from: classes.dex */
public enum YogaGutter {
    COLUMN(0),
    ROW(1),
    ALL(2);

    private final int mIntValue;

    YogaGutter(int i) {
        this.mIntValue = i;
    }

    public int intValue() {
        return this.mIntValue;
    }

    public static YogaGutter fromInt(int i) {
        if (i == 0) {
            return COLUMN;
        }
        if (i == 1) {
            return ROW;
        }
        if (i == 2) {
            return ALL;
        }
        throw new IllegalArgumentException("Unknown enum value: " + i);
    }
}
