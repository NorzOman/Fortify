package com.facebook.imagepipeline.decoder;

import com.facebook.imagepipeline.common.ImageDecodeOptions;
import com.facebook.imagepipeline.image.CloseableImage;
import com.facebook.imagepipeline.image.EncodedImage;
import com.facebook.imagepipeline.image.QualityInfo;
import kotlin.Metadata;

/* compiled from: ImageDecoder.kt */
@Metadata(d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bæ\u0080\u0001\u0018\u00002\u00020\u0001J*\u0010\u0002\u001a\u0004\u0018\u00010\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000bH&¨\u0006\f"}, d2 = {"Lcom/facebook/imagepipeline/decoder/ImageDecoder;", "", "decode", "Lcom/facebook/imagepipeline/image/CloseableImage;", "encodedImage", "Lcom/facebook/imagepipeline/image/EncodedImage;", "length", "", "qualityInfo", "Lcom/facebook/imagepipeline/image/QualityInfo;", "options", "Lcom/facebook/imagepipeline/common/ImageDecodeOptions;", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ImageDecoder {
    CloseableImage decode(EncodedImage encodedImage, int length, QualityInfo qualityInfo, ImageDecodeOptions options);
}
