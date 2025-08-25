package com.facebook.fresco.ui.common;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: SimpleImagePerfNotifier.kt */
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0018\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000bH\u0016J\u0018\u0010\f\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\u000eH\u0016R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000f"}, d2 = {"Lcom/facebook/fresco/ui/common/SimpleImagePerfNotifier;", "Lcom/facebook/fresco/ui/common/ImagePerfNotifier;", "imagePerfDataListener", "Lcom/facebook/fresco/ui/common/ImagePerfDataListener;", "<init>", "(Lcom/facebook/fresco/ui/common/ImagePerfDataListener;)V", "notifyVisibilityUpdated", "", "state", "Lcom/facebook/fresco/ui/common/ImagePerfState;", "visibilityState", "Lcom/facebook/fresco/ui/common/VisibilityState;", "notifyStatusUpdated", "imageLoadStatus", "Lcom/facebook/fresco/ui/common/ImageLoadStatus;", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class SimpleImagePerfNotifier implements ImagePerfNotifier {
    private final ImagePerfDataListener imagePerfDataListener;

    public SimpleImagePerfNotifier(ImagePerfDataListener imagePerfDataListener) {
        Intrinsics.checkNotNullParameter(imagePerfDataListener, "imagePerfDataListener");
        this.imagePerfDataListener = imagePerfDataListener;
    }

    @Override // com.facebook.fresco.ui.common.ImagePerfNotifier
    public void notifyVisibilityUpdated(ImagePerfState state, VisibilityState visibilityState) {
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(visibilityState, "visibilityState");
        this.imagePerfDataListener.onImageVisibilityUpdated(state.snapshot(), visibilityState);
    }

    @Override // com.facebook.fresco.ui.common.ImagePerfNotifier
    public void notifyStatusUpdated(ImagePerfState state, ImageLoadStatus imageLoadStatus) {
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(imageLoadStatus, "imageLoadStatus");
        this.imagePerfDataListener.onImageLoadStatusUpdated(state.snapshot(), imageLoadStatus);
    }
}
