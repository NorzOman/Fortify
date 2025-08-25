package com.facebook.imagepipeline.animated.factory;

import android.content.Context;
import com.facebook.imagepipeline.decoder.ImageDecoder;
import com.facebook.imagepipeline.drawable.DrawableFactory;
import kotlin.Metadata;

/* compiled from: AnimatedFactory.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\bg\u0018\u00002\u00020\u0001J\u0014\u0010\u0002\u001a\u0004\u0018\u00010\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005H&R\u0014\u0010\u0006\u001a\u0004\u0018\u00010\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\tR\u0014\u0010\n\u001a\u0004\u0018\u00010\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\u000b\u0010\t¨\u0006\f"}, d2 = {"Lcom/facebook/imagepipeline/animated/factory/AnimatedFactory;", "", "getAnimatedDrawableFactory", "Lcom/facebook/imagepipeline/drawable/DrawableFactory;", "context", "Landroid/content/Context;", "gifDecoder", "Lcom/facebook/imagepipeline/decoder/ImageDecoder;", "getGifDecoder", "()Lcom/facebook/imagepipeline/decoder/ImageDecoder;", "webPDecoder", "getWebPDecoder", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface AnimatedFactory {
    DrawableFactory getAnimatedDrawableFactory(Context context);

    ImageDecoder getGifDecoder();

    ImageDecoder getWebPDecoder();
}
