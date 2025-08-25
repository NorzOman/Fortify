package com.facebook.yoga;

/* loaded from: classes.dex */
public class YogaMeasureOutput {
    public static long make(float f, float f2) {
        return Float.floatToRawIntBits(f2) | (Float.floatToRawIntBits(f) << 32);
    }

    public static long make(int i, int i2) {
        return make(i, i2);
    }

    public static float getWidth(long j) {
        return Float.intBitsToFloat((int) (j >> 32));
    }

    public static float getHeight(long j) {
        return Float.intBitsToFloat((int) j);
    }
}
