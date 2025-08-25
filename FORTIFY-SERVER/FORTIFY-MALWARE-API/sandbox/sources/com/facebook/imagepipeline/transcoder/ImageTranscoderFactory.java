package com.facebook.imagepipeline.transcoder;

import com.facebook.imageformat.ImageFormat;
import kotlin.Metadata;

/* compiled from: ImageTranscoderFactory.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\bf\u0018\u00002\u00020\u0001J\u001a\u0010\u0002\u001a\u0004\u0018\u00010\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H&¨\u0006\b"}, d2 = {"Lcom/facebook/imagepipeline/transcoder/ImageTranscoderFactory;", "", "createImageTranscoder", "Lcom/facebook/imagepipeline/transcoder/ImageTranscoder;", "imageFormat", "Lcom/facebook/imageformat/ImageFormat;", "isResizingEnabled", "", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ImageTranscoderFactory {
    ImageTranscoder createImageTranscoder(ImageFormat imageFormat, boolean isResizingEnabled);
}
