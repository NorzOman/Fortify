package com.facebook.imagepipeline.bitmaps;

import android.graphics.Bitmap;
import com.facebook.common.logging.FLog;
import com.facebook.common.memory.PooledByteBuffer;
import com.facebook.common.references.CloseableReference;
import com.facebook.imageformat.DefaultImageFormats;
import com.facebook.imagepipeline.core.CloseableReferenceFactory;
import com.facebook.imagepipeline.image.EncodedImage;
import com.facebook.imagepipeline.platform.PlatformDecoder;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: HoneycombBitmapFactory.kt */
@Metadata(d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\b\u0007\u0018\u0000 \u00152\u00020\u0001:\u0001\u0015B\u001f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0004\b\b\u0010\tJ&\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000e0\r2\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u0013H\u0017J&\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u000e0\r2\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u0013H\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u000bX\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u0016"}, d2 = {"Lcom/facebook/imagepipeline/bitmaps/HoneycombBitmapFactory;", "Lcom/facebook/imagepipeline/bitmaps/PlatformBitmapFactory;", "jpegGenerator", "Lcom/facebook/imagepipeline/bitmaps/EmptyJpegGenerator;", "purgeableDecoder", "Lcom/facebook/imagepipeline/platform/PlatformDecoder;", "closeableReferenceFactory", "Lcom/facebook/imagepipeline/core/CloseableReferenceFactory;", "<init>", "(Lcom/facebook/imagepipeline/bitmaps/EmptyJpegGenerator;Lcom/facebook/imagepipeline/platform/PlatformDecoder;Lcom/facebook/imagepipeline/core/CloseableReferenceFactory;)V", "immutableBitmapFallback", "", "createBitmapInternal", "Lcom/facebook/common/references/CloseableReference;", "Landroid/graphics/Bitmap;", "width", "", "height", "bitmapConfig", "Landroid/graphics/Bitmap$Config;", "createFallbackBitmap", "Companion", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class HoneycombBitmapFactory extends PlatformBitmapFactory {
    private static final String TAG = "HoneycombBitmapFactory";
    private final CloseableReferenceFactory closeableReferenceFactory;
    private boolean immutableBitmapFallback;
    private final EmptyJpegGenerator jpegGenerator;
    private final PlatformDecoder purgeableDecoder;

    public HoneycombBitmapFactory(EmptyJpegGenerator jpegGenerator, PlatformDecoder purgeableDecoder, CloseableReferenceFactory closeableReferenceFactory) {
        Intrinsics.checkNotNullParameter(jpegGenerator, "jpegGenerator");
        Intrinsics.checkNotNullParameter(purgeableDecoder, "purgeableDecoder");
        Intrinsics.checkNotNullParameter(closeableReferenceFactory, "closeableReferenceFactory");
        this.jpegGenerator = jpegGenerator;
        this.purgeableDecoder = purgeableDecoder;
        this.closeableReferenceFactory = closeableReferenceFactory;
    }

    @Override // com.facebook.imagepipeline.bitmaps.PlatformBitmapFactory
    public CloseableReference<Bitmap> createBitmapInternal(int width, int height, Bitmap.Config bitmapConfig) throws Throwable {
        Intrinsics.checkNotNullParameter(bitmapConfig, "bitmapConfig");
        if (this.immutableBitmapFallback) {
            return createFallbackBitmap(width, height, bitmapConfig);
        }
        CloseableReference<PooledByteBuffer> closeableReferenceGenerate = this.jpegGenerator.generate((short) width, (short) height);
        Intrinsics.checkNotNullExpressionValue(closeableReferenceGenerate, "generate(...)");
        try {
            EncodedImage encodedImage = new EncodedImage(closeableReferenceGenerate);
            encodedImage.setImageFormat(DefaultImageFormats.JPEG);
            try {
                CloseableReference<Bitmap> closeableReferenceDecodeJPEGFromEncodedImage = this.purgeableDecoder.decodeJPEGFromEncodedImage(encodedImage, bitmapConfig, null, closeableReferenceGenerate.get().size());
                if (closeableReferenceDecodeJPEGFromEncodedImage == null) {
                    throw new IllegalStateException("Required value was null.".toString());
                }
                if (!closeableReferenceDecodeJPEGFromEncodedImage.get().isMutable()) {
                    CloseableReference.closeSafely(closeableReferenceDecodeJPEGFromEncodedImage);
                    this.immutableBitmapFallback = true;
                    FLog.wtf(TAG, "Immutable bitmap returned by decoder");
                    return createFallbackBitmap(width, height, bitmapConfig);
                }
                closeableReferenceDecodeJPEGFromEncodedImage.get().setHasAlpha(true);
                closeableReferenceDecodeJPEGFromEncodedImage.get().eraseColor(0);
                return closeableReferenceDecodeJPEGFromEncodedImage;
            } finally {
                EncodedImage.closeSafely(encodedImage);
            }
        } finally {
            closeableReferenceGenerate.close();
        }
    }

    private final CloseableReference<Bitmap> createFallbackBitmap(int width, int height, Bitmap.Config bitmapConfig) {
        CloseableReference<Bitmap> closeableReferenceCreate = this.closeableReferenceFactory.create(Bitmap.createBitmap(width, height, bitmapConfig), SimpleBitmapReleaser.getInstance());
        Intrinsics.checkNotNullExpressionValue(closeableReferenceCreate, "create(...)");
        return closeableReferenceCreate;
    }
}
