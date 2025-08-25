package com.facebook.yoga;

/* loaded from: classes.dex */
public enum YogaDisplay {
    FLEX(0),
    NONE(1),
    CONTENTS(2);

    private final int mIntValue;

    YogaDisplay(int i) {
        this.mIntValue = i;
    }

    public int intValue() {
        return this.mIntValue;
    }

    public static YogaDisplay fromInt(int i) {
        if (i == 0) {
            return FLEX;
        }
        if (i == 1) {
            return NONE;
        }
        if (i == 2) {
            return CONTENTS;
        }
        throw new IllegalArgumentException("Unknown enum value: " + i);
    }
}
