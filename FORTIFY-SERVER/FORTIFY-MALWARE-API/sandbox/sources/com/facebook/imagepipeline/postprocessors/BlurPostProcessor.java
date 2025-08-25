package com.facebook.imagepipeline.postprocessors;

import android.content.Context;
import android.graphics.Bitmap;
import com.facebook.cache.common.CacheKey;
import com.facebook.cache.common.SimpleCacheKey;
import com.facebook.common.internal.Preconditions;
import com.facebook.imagepipeline.filter.IterativeBoxBlurFilter;
import com.facebook.imagepipeline.filter.RenderScriptBlurFilter;
import com.facebook.imagepipeline.request.BasePostprocessor;
import java.util.Arrays;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.StringCompanionObject;

/* compiled from: BlurPostProcessor.kt */
@Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u0000 \u00172\u00020\u0001:\u0001\u0017B#\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u0006\u001a\u00020\u0003¢\u0006\u0004\b\u0007\u0010\bJ\b\u0010\u0010\u001a\u00020\u000fH\u0016J\u0018\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0014H\u0016J\u0010\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0016\u001a\u00020\u0014H\u0016R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\nR\u0011\u0010\u0004\u001a\u00020\u0005¢\u0006\b\n\u0000\u001a\u0004\b\u000b\u0010\fR\u0011\u0010\u0006\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\nR\u000e\u0010\u000e\u001a\u00020\u000fX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0018"}, d2 = {"Lcom/facebook/imagepipeline/postprocessors/BlurPostProcessor;", "Lcom/facebook/imagepipeline/request/BasePostprocessor;", "blurRadius", "", "context", "Landroid/content/Context;", "iterations", "<init>", "(ILandroid/content/Context;I)V", "getBlurRadius", "()I", "getContext", "()Landroid/content/Context;", "getIterations", "cacheKey", "Lcom/facebook/cache/common/CacheKey;", "getPostprocessorCacheKey", "process", "", "destBitmap", "Landroid/graphics/Bitmap;", "sourceBitmap", "bitmap", "Companion", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class BlurPostProcessor extends BasePostprocessor {
    private static final int DEFAULT_ITERATIONS = 3;
    private final int blurRadius;
    private final CacheKey cacheKey;
    private final Context context;
    private final int iterations;
    private static final boolean canUseRenderScript = RenderScriptBlurFilter.canUseRenderScript();

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public BlurPostProcessor(int i, Context context) {
        this(i, context, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ BlurPostProcessor(int i, Context context, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(i, context, (i3 & 4) != 0 ? 3 : i2);
    }

    public final int getBlurRadius() {
        return this.blurRadius;
    }

    public final Context getContext() {
        return this.context;
    }

    public final int getIterations() {
        return this.iterations;
    }

    public BlurPostProcessor(int i, Context context, int i2) {
        String str;
        Intrinsics.checkNotNullParameter(context, "context");
        this.blurRadius = i;
        this.context = context;
        this.iterations = i2;
        Preconditions.checkArgument(Boolean.valueOf(i > 0 && i <= 25));
        Preconditions.checkArgument(Boolean.valueOf(i2 > 0));
        if (canUseRenderScript) {
            StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
            str = String.format(null, "IntrinsicBlur;%d", Arrays.copyOf(new Object[]{Integer.valueOf(i)}, 1));
            Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        } else {
            StringCompanionObject stringCompanionObject2 = StringCompanionObject.INSTANCE;
            str = String.format(null, "IterativeBoxBlur;%d;%d", Arrays.copyOf(new Object[]{Integer.valueOf(i2), Integer.valueOf(i)}, 2));
            Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        }
        this.cacheKey = new SimpleCacheKey(str);
    }

    @Override // com.facebook.imagepipeline.request.BasePostprocessor, com.facebook.imagepipeline.request.Postprocessor
    /* renamed from: getPostprocessorCacheKey, reason: from getter */
    public CacheKey getCacheKey() {
        return this.cacheKey;
    }

    @Override // com.facebook.imagepipeline.request.BasePostprocessor
    public void process(Bitmap destBitmap, Bitmap sourceBitmap) throws Throwable {
        Intrinsics.checkNotNullParameter(destBitmap, "destBitmap");
        Intrinsics.checkNotNullParameter(sourceBitmap, "sourceBitmap");
        if (canUseRenderScript) {
            RenderScriptBlurFilter.blurBitmap(destBitmap, sourceBitmap, this.context, this.blurRadius);
        } else {
            super.process(destBitmap, sourceBitmap);
        }
    }

    @Override // com.facebook.imagepipeline.request.BasePostprocessor
    public void process(Bitmap bitmap) {
        Intrinsics.checkNotNullParameter(bitmap, "bitmap");
        IterativeBoxBlurFilter.boxBlurBitmapInPlace(bitmap, this.iterations, this.blurRadius);
    }
}
