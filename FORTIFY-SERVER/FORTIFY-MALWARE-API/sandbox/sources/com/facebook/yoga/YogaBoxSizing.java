package com.facebook.yoga;

/* loaded from: classes.dex */
public enum YogaBoxSizing {
    BORDER_BOX(0),
    CONTENT_BOX(1);

    private final int mIntValue;

    YogaBoxSizing(int i) {
        this.mIntValue = i;
    }

    public int intValue() {
        return this.mIntValue;
    }

    public static YogaBoxSizing fromInt(int i) {
        if (i == 0) {
            return BORDER_BOX;
        }
        if (i == 1) {
            return CONTENT_BOX;
        }
        throw new IllegalArgumentException("Unknown enum value: " + i);
    }
}
