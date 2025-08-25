package com.facebook.imagepipeline.nativecode;

import android.graphics.Bitmap;
import com.facebook.common.internal.Preconditions;

/* loaded from: classes.dex */
public class NativeRoundingFilter {
    private static native void nativeAddRoundedCornersFilter(Bitmap bitmap, int i, int i2, int i3, int i4);

    private static native void nativeToCircleFastFilter(Bitmap bitmap, boolean z);

    private static native void nativeToCircleFilter(Bitmap bitmap, boolean z);

    private static native void nativeToCircleWithBorderFilter(Bitmap bitmap, int i, int i2, boolean z);

    static {
        NativeFiltersLoader.load();
    }

    public static void toCircle(Bitmap bitmap) {
        toCircle(bitmap, false);
    }

    public static void toCircleFast(Bitmap bitmap) {
        toCircleFast(bitmap, false);
    }

    public static void addRoundedCorners(Bitmap bitmap, int i, int i2, int i3, int i4) {
        nativeAddRoundedCornersFilter(bitmap, i, i2, i3, i4);
    }

    public static void toCircle(Bitmap bitmap, boolean z) {
        Preconditions.checkNotNull(bitmap);
        if (bitmap.getWidth() < 3 || bitmap.getHeight() < 3) {
            return;
        }
        nativeToCircleFilter(bitmap, z);
    }

    public static void toCircleFast(Bitmap bitmap, boolean z) {
        Preconditions.checkNotNull(bitmap);
        if (bitmap.getWidth() < 3 || bitmap.getHeight() < 3) {
            return;
        }
        nativeToCircleFastFilter(bitmap, z);
    }

    public static void toCircleWithBorder(Bitmap bitmap, int i, int i2, boolean z) {
        Preconditions.checkNotNull(bitmap);
        if (bitmap.getWidth() < 3 || bitmap.getHeight() < 3) {
            return;
        }
        nativeToCircleWithBorderFilter(bitmap, i, i2, z);
    }
}
