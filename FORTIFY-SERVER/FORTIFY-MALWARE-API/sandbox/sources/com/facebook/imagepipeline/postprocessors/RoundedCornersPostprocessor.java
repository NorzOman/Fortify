package com.facebook.imagepipeline.postprocessors;

import android.graphics.Bitmap;
import com.facebook.cache.common.CacheKey;
import com.facebook.cache.common.SimpleCacheKey;
import com.facebook.imagepipeline.nativecode.NativeRoundingFilter;
import com.facebook.imagepipeline.request.BasePostprocessor;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class RoundedCornersPostprocessor extends BasePostprocessor {

    @Nullable
    private CacheKey mCacheKey;

    @Override // com.facebook.imagepipeline.request.BasePostprocessor
    public void process(Bitmap bitmap) {
        int iMin = Math.min(bitmap.getHeight(), bitmap.getWidth());
        NativeRoundingFilter.addRoundedCorners(bitmap, iMin / 2, iMin / 3, iMin / 4, iMin / 5);
    }

    @Override // com.facebook.imagepipeline.request.BasePostprocessor, com.facebook.imagepipeline.request.Postprocessor
    @Nullable
    public CacheKey getPostprocessorCacheKey() {
        if (this.mCacheKey == null) {
            this.mCacheKey = new SimpleCacheKey("RoundedCornersPostprocessor");
        }
        return this.mCacheKey;
    }
}
