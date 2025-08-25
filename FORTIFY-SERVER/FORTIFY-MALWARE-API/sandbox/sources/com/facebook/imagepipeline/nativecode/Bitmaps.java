package com.facebook.imagepipeline.nativecode;

import android.graphics.Bitmap;
import com.facebook.common.internal.Preconditions;

/* loaded from: classes.dex */
public class Bitmaps {
    private static native void nativeCopyBitmap(Bitmap bitmap, int i, Bitmap bitmap2, int i2, int i3);

    static {
        ImagePipelineNativeLoader.load();
    }

    public static void copyBitmap(Bitmap bitmap, Bitmap bitmap2) {
        Preconditions.checkArgument(Boolean.valueOf(bitmap2.getConfig() == bitmap.getConfig()));
        Preconditions.checkArgument(Boolean.valueOf(bitmap.isMutable()));
        Preconditions.checkArgument(Boolean.valueOf(bitmap.getWidth() == bitmap2.getWidth()));
        Preconditions.checkArgument(Boolean.valueOf(bitmap.getHeight() == bitmap2.getHeight()));
        nativeCopyBitmap(bitmap, bitmap.getRowBytes(), bitmap2, bitmap2.getRowBytes(), bitmap.getHeight());
    }
}
