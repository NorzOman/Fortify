package com.facebook.yoga;

/* loaded from: classes.dex */
public enum YogaErrata {
    NONE(0),
    STRETCH_FLEX_BASIS(1),
    ABSOLUTE_POSITION_WITHOUT_INSETS_EXCLUDES_PADDING(2),
    ABSOLUTE_PERCENT_AGAINST_INNER_SIZE(4),
    ALL(Integer.MAX_VALUE),
    CLASSIC(2147483646);

    private final int mIntValue;

    YogaErrata(int i) {
        this.mIntValue = i;
    }

    public int intValue() {
        return this.mIntValue;
    }

    public static YogaErrata fromInt(int i) {
        if (i == 0) {
            return NONE;
        }
        if (i == 1) {
            return STRETCH_FLEX_BASIS;
        }
        if (i == 2) {
            return ABSOLUTE_POSITION_WITHOUT_INSETS_EXCLUDES_PADDING;
        }
        if (i == 4) {
            return ABSOLUTE_PERCENT_AGAINST_INNER_SIZE;
        }
        switch (i) {
            case 2147483646:
                return CLASSIC;
            case Integer.MAX_VALUE:
                return ALL;
            default:
                throw new IllegalArgumentException("Unknown enum value: " + i);
        }
    }
}
