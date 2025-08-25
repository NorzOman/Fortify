package com.facebook.imagepipeline.nativecode;

import com.facebook.imageformat.DefaultImageFormats;
import com.facebook.imageformat.ImageFormat;
import com.facebook.imagepipeline.transcoder.ImageTranscoder;
import com.facebook.imagepipeline.transcoder.ImageTranscoderFactory;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class NativeJpegTranscoderFactory implements ImageTranscoderFactory {
    private final boolean mEnsureTranscoderLibraryLoaded;
    private final int mMaxBitmapSize;
    private final boolean mUseDownSamplingRatio;

    public NativeJpegTranscoderFactory(int i, boolean z, boolean z2) {
        this.mMaxBitmapSize = i;
        this.mUseDownSamplingRatio = z;
        this.mEnsureTranscoderLibraryLoaded = z2;
    }

    @Override // com.facebook.imagepipeline.transcoder.ImageTranscoderFactory
    @Nullable
    public ImageTranscoder createImageTranscoder(ImageFormat imageFormat, boolean z) {
        if (imageFormat != DefaultImageFormats.JPEG) {
            return null;
        }
        return new NativeJpegTranscoder(z, this.mMaxBitmapSize, this.mUseDownSamplingRatio, this.mEnsureTranscoderLibraryLoaded);
    }
}
