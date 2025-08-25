package com.facebook.imagepipeline.image;

import com.facebook.common.references.HasBitmap;
import com.facebook.fresco.middleware.HasExtraData;
import java.io.Closeable;

/* loaded from: classes.dex */
public interface CloseableImage extends Closeable, ImageInfo, HasBitmap, HasExtraData {
    @Override // java.io.Closeable, java.lang.AutoCloseable
    void close();

    int getHeight();

    ImageInfo getImageInfo();

    QualityInfo getQualityInfo();

    int getSizeInBytes();

    int getWidth();

    boolean isClosed();

    boolean isStateful();
}
