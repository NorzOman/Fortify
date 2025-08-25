package com.facebook.drawee.debug.listener;

import android.graphics.drawable.Animatable;
import com.facebook.drawee.controller.BaseControllerListener;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ImageLoadingTimeControllerListener.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\u0018\u00002\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001B\u0011\u0012\b\u0010\u0003\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b\u0005\u0010\u0006J\u001a\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\r2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0002H\u0016J$\u0010\u000f\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\r2\b\u0010\u0010\u001a\u0004\u0018\u00010\u00022\b\u0010\u0011\u001a\u0004\u0018\u00010\u0012H\u0016R\u0010\u0010\u0003\u001a\u0004\u0018\u00010\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\bX\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u0013"}, d2 = {"Lcom/facebook/drawee/debug/listener/ImageLoadingTimeControllerListener;", "Lcom/facebook/drawee/controller/BaseControllerListener;", "", "imageLoadingTimeListener", "Lcom/facebook/drawee/debug/listener/ImageLoadingTimeListener;", "<init>", "(Lcom/facebook/drawee/debug/listener/ImageLoadingTimeListener;)V", "requestSubmitTimeMs", "", "finalImageSetTimeMs", "onSubmit", "", "id", "", "callerContext", "onFinalImageSet", "imageInfo", "animatable", "Landroid/graphics/drawable/Animatable;", "drawee_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ImageLoadingTimeControllerListener extends BaseControllerListener<Object> {
    private final ImageLoadingTimeListener imageLoadingTimeListener;
    private long requestSubmitTimeMs = -1;
    private long finalImageSetTimeMs = -1;

    public ImageLoadingTimeControllerListener(ImageLoadingTimeListener imageLoadingTimeListener) {
        this.imageLoadingTimeListener = imageLoadingTimeListener;
    }

    @Override // com.facebook.drawee.controller.BaseControllerListener, com.facebook.drawee.controller.ControllerListener
    public void onSubmit(String id, Object callerContext) {
        Intrinsics.checkNotNullParameter(id, "id");
        this.requestSubmitTimeMs = System.currentTimeMillis();
    }

    @Override // com.facebook.drawee.controller.BaseControllerListener, com.facebook.drawee.controller.ControllerListener
    public void onFinalImageSet(String id, Object imageInfo, Animatable animatable) {
        Intrinsics.checkNotNullParameter(id, "id");
        long jCurrentTimeMillis = System.currentTimeMillis();
        this.finalImageSetTimeMs = jCurrentTimeMillis;
        ImageLoadingTimeListener imageLoadingTimeListener = this.imageLoadingTimeListener;
        if (imageLoadingTimeListener != null) {
            imageLoadingTimeListener.onFinalImageSet(jCurrentTimeMillis - this.requestSubmitTimeMs);
        }
    }
}
