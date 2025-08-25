package com.facebook.imagepipeline.datasource;

import android.graphics.Bitmap;
import com.facebook.common.references.CloseableReference;
import com.facebook.datasource.BaseDataSubscriber;
import com.facebook.datasource.DataSource;
import com.facebook.imagepipeline.image.CloseableImage;
import com.facebook.imagepipeline.image.CloseableStaticBitmap;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public abstract class BaseBitmapReferenceDataSubscriber extends BaseDataSubscriber<CloseableReference<CloseableImage>> {
    protected abstract void onNewResultImpl(@Nullable CloseableReference<Bitmap> closeableReference);

    @Override // com.facebook.datasource.BaseDataSubscriber
    public void onNewResultImpl(DataSource<CloseableReference<CloseableImage>> dataSource) {
        if (dataSource.isFinished()) {
            CloseableReference<CloseableImage> result = dataSource.getResult();
            CloseableReference<Bitmap> closeableReferenceCloneUnderlyingBitmapReference = (result == null || !(result.get() instanceof CloseableStaticBitmap)) ? null : ((CloseableStaticBitmap) result.get()).cloneUnderlyingBitmapReference();
            try {
                onNewResultImpl(closeableReferenceCloneUnderlyingBitmapReference);
            } finally {
                CloseableReference.closeSafely(closeableReferenceCloneUnderlyingBitmapReference);
                CloseableReference.closeSafely(result);
            }
        }
    }
}
