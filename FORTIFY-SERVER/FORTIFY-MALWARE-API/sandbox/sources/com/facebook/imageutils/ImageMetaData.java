package com.facebook.imageutils;

import android.graphics.ColorSpace;
import kotlin.Metadata;
import kotlin.Pair;

/* compiled from: ImageMetaData.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\u0018\u00002\u00020\u0001B!\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\b\u0010\u0005\u001a\u0004\u0018\u00010\u0006¢\u0006\u0004\b\u0007\u0010\bR\u0013\u0010\u0005\u001a\u0004\u0018\u00010\u0006¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\nR\u001f\u0010\u000b\u001a\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\f¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000e¨\u0006\u000f"}, d2 = {"Lcom/facebook/imageutils/ImageMetaData;", "", "width", "", "height", "colorSpace", "Landroid/graphics/ColorSpace;", "<init>", "(IILandroid/graphics/ColorSpace;)V", "getColorSpace", "()Landroid/graphics/ColorSpace;", "dimensions", "Lkotlin/Pair;", "getDimensions", "()Lkotlin/Pair;", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ImageMetaData {
    private final ColorSpace colorSpace;
    private final Pair<Integer, Integer> dimensions;

    public ImageMetaData(int i, int i2, ColorSpace colorSpace) {
        this.colorSpace = colorSpace;
        this.dimensions = (i == -1 || i2 == -1) ? null : new Pair<>(Integer.valueOf(i), Integer.valueOf(i2));
    }

    public final ColorSpace getColorSpace() {
        return this.colorSpace;
    }

    public final Pair<Integer, Integer> getDimensions() {
        return this.dimensions;
    }
}
