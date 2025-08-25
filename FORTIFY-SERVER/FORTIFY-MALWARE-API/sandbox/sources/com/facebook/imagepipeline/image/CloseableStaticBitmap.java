package com.facebook.imagepipeline.image;

import android.graphics.Bitmap;
import com.facebook.common.references.CloseableReference;
import com.facebook.common.references.ResourceReleaser;

/* loaded from: classes.dex */
public interface CloseableStaticBitmap extends CloseableBitmap {
    CloseableReference<Bitmap> cloneUnderlyingBitmapReference();

    CloseableReference<Bitmap> convertToBitmapReference();

    int getExifOrientation();

    int getRotationAngle();

    static CloseableStaticBitmap of(Bitmap bitmap, ResourceReleaser<Bitmap> resourceReleaser, QualityInfo qualityInfo, int i) {
        return of(bitmap, resourceReleaser, qualityInfo, i, 0);
    }

    static CloseableStaticBitmap of(CloseableReference<Bitmap> closeableReference, QualityInfo qualityInfo, int i) {
        return of(closeableReference, qualityInfo, i, 0);
    }

    static CloseableStaticBitmap of(Bitmap bitmap, ResourceReleaser<Bitmap> resourceReleaser, QualityInfo qualityInfo, int i, int i2) {
        if (BaseCloseableStaticBitmap.shouldUseSimpleCloseableStaticBitmap()) {
            return new BaseCloseableStaticBitmap(bitmap, resourceReleaser, qualityInfo, i, i2);
        }
        return new DefaultCloseableStaticBitmap(bitmap, resourceReleaser, qualityInfo, i, i2);
    }

    static CloseableStaticBitmap of(CloseableReference<Bitmap> closeableReference, QualityInfo qualityInfo, int i, int i2) {
        if (BaseCloseableStaticBitmap.shouldUseSimpleCloseableStaticBitmap()) {
            return new BaseCloseableStaticBitmap(closeableReference, qualityInfo, i, i2);
        }
        return new DefaultCloseableStaticBitmap(closeableReference, qualityInfo, i, i2);
    }
}
