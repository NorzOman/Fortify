package com.facebook.fresco.ui.common;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: NoOpImagePerfNotifier.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0016J\u0018\u0010\n\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\fH\u0016¨\u0006\r"}, d2 = {"Lcom/facebook/fresco/ui/common/NoOpImagePerfNotifier;", "Lcom/facebook/fresco/ui/common/ImagePerfNotifier;", "<init>", "()V", "notifyVisibilityUpdated", "", "state", "Lcom/facebook/fresco/ui/common/ImagePerfState;", "visibilityState", "Lcom/facebook/fresco/ui/common/VisibilityState;", "notifyStatusUpdated", "imageLoadStatus", "Lcom/facebook/fresco/ui/common/ImageLoadStatus;", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class NoOpImagePerfNotifier implements ImagePerfNotifier {
    public static final NoOpImagePerfNotifier INSTANCE = new NoOpImagePerfNotifier();

    @Override // com.facebook.fresco.ui.common.ImagePerfNotifier
    public void notifyStatusUpdated(ImagePerfState state, ImageLoadStatus imageLoadStatus) {
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(imageLoadStatus, "imageLoadStatus");
    }

    @Override // com.facebook.fresco.ui.common.ImagePerfNotifier
    public void notifyVisibilityUpdated(ImagePerfState state, VisibilityState visibilityState) {
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(visibilityState, "visibilityState");
    }

    private NoOpImagePerfNotifier() {
    }
}
