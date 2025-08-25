package com.facebook.common.util;

import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class HashCodeUtil {
    private static final int X = 31;

    public static int hashCode(int i) {
        return i + 31;
    }

    public static int hashCode(int i, int i2) {
        return ((i + 31) * 31) + i2;
    }

    public static int hashCode(int i, int i2, int i3) {
        return ((((i + 31) * 31) + i2) * 31) + i3;
    }

    public static int hashCode(int i, int i2, int i3, int i4) {
        return ((((((i + 31) * 31) + i2) * 31) + i3) * 31) + i4;
    }

    public static int hashCode(int i, int i2, int i3, int i4, int i5) {
        return ((((((((i + 31) * 31) + i2) * 31) + i3) * 31) + i4) * 31) + i5;
    }

    public static int hashCode(int i, int i2, int i3, int i4, int i5, int i6) {
        return ((((((((((i + 31) * 31) + i2) * 31) + i3) * 31) + i4) * 31) + i5) * 31) + i6;
    }

    public static int hashCode(@Nullable Object obj) {
        return hashCode(obj == null ? 0 : obj.hashCode());
    }

    public static int hashCode(@Nullable Object obj, @Nullable Object obj2) {
        return hashCode(obj == null ? 0 : obj.hashCode(), obj2 != null ? obj2.hashCode() : 0);
    }

    public static int hashCode(@Nullable Object obj, @Nullable Object obj2, @Nullable Object obj3) {
        return hashCode(obj == null ? 0 : obj.hashCode(), obj2 == null ? 0 : obj2.hashCode(), obj3 != null ? obj3.hashCode() : 0);
    }

    public static int hashCode(@Nullable Object obj, @Nullable Object obj2, @Nullable Object obj3, @Nullable Object obj4) {
        return hashCode(obj == null ? 0 : obj.hashCode(), obj2 == null ? 0 : obj2.hashCode(), obj3 == null ? 0 : obj3.hashCode(), obj4 != null ? obj4.hashCode() : 0);
    }

    public static int hashCode(@Nullable Object obj, @Nullable Object obj2, @Nullable Object obj3, @Nullable Object obj4, @Nullable Object obj5) {
        return hashCode(obj == null ? 0 : obj.hashCode(), obj2 == null ? 0 : obj2.hashCode(), obj3 == null ? 0 : obj3.hashCode(), obj4 == null ? 0 : obj4.hashCode(), obj5 != null ? obj5.hashCode() : 0);
    }

    public static int hashCode(@Nullable Object obj, @Nullable Object obj2, @Nullable Object obj3, @Nullable Object obj4, @Nullable Object obj5, @Nullable Object obj6) {
        return hashCode(obj == null ? 0 : obj.hashCode(), obj2 == null ? 0 : obj2.hashCode(), obj3 == null ? 0 : obj3.hashCode(), obj4 == null ? 0 : obj4.hashCode(), obj5 == null ? 0 : obj5.hashCode(), obj6 != null ? obj6.hashCode() : 0);
    }
}
