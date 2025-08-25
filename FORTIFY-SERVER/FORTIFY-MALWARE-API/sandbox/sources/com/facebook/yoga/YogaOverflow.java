package com.facebook.yoga;

/* loaded from: classes.dex */
public enum YogaOverflow {
    VISIBLE(0),
    HIDDEN(1),
    SCROLL(2);

    private final int mIntValue;

    YogaOverflow(int i) {
        this.mIntValue = i;
    }

    public int intValue() {
        return this.mIntValue;
    }

    public static YogaOverflow fromInt(int i) {
        if (i == 0) {
            return VISIBLE;
        }
        if (i == 1) {
            return HIDDEN;
        }
        if (i == 2) {
            return SCROLL;
        }
        throw new IllegalArgumentException("Unknown enum value: " + i);
    }
}
