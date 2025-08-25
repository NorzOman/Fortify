package com.facebook.imagepipeline.transcoder;

import com.facebook.imageformat.ImageFormat;

/* loaded from: classes.dex */
public class SimpleImageTranscoderFactory implements ImageTranscoderFactory {
    private final int mMaxBitmapSize;

    public SimpleImageTranscoderFactory(int i) {
        this.mMaxBitmapSize = i;
    }

    @Override // com.facebook.imagepipeline.transcoder.ImageTranscoderFactory
    public ImageTranscoder createImageTranscoder(ImageFormat imageFormat, boolean z) {
        return new SimpleImageTranscoder(z, this.mMaxBitmapSize);
    }
}
