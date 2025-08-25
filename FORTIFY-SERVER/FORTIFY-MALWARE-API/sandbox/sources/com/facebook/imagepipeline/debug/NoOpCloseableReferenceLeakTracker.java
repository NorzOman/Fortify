package com.facebook.imagepipeline.debug;

import com.facebook.common.references.SharedReference;
import com.facebook.imagepipeline.debug.CloseableReferenceLeakTracker;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: NoOpCloseableReferenceLeakTracker.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0003\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\"\u0010\u0004\u001a\u00020\u00052\u000e\u0010\u0006\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\b0\u00072\b\u0010\t\u001a\u0004\u0018\u00010\nH\u0016J\u0012\u0010\u000b\u001a\u00020\u00052\b\u0010\f\u001a\u0004\u0018\u00010\rH\u0016R\u0014\u0010\u000e\u001a\u00020\u000f8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u0010¨\u0006\u0011"}, d2 = {"Lcom/facebook/imagepipeline/debug/NoOpCloseableReferenceLeakTracker;", "Lcom/facebook/imagepipeline/debug/CloseableReferenceLeakTracker;", "<init>", "()V", "trackCloseableReferenceLeak", "", "reference", "Lcom/facebook/common/references/SharedReference;", "", "stacktrace", "", "setListener", "listener", "Lcom/facebook/imagepipeline/debug/CloseableReferenceLeakTracker$Listener;", "isSet", "", "()Z", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class NoOpCloseableReferenceLeakTracker implements CloseableReferenceLeakTracker {
    @Override // com.facebook.imagepipeline.debug.CloseableReferenceLeakTracker
    public boolean isSet() {
        return false;
    }

    @Override // com.facebook.imagepipeline.debug.CloseableReferenceLeakTracker
    public void setListener(CloseableReferenceLeakTracker.Listener listener) {
    }

    @Override // com.facebook.imagepipeline.debug.CloseableReferenceLeakTracker
    public void trackCloseableReferenceLeak(SharedReference<Object> reference, Throwable stacktrace) {
        Intrinsics.checkNotNullParameter(reference, "reference");
    }
}
