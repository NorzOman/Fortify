package com.facebook.imagepipeline.debug;

import com.facebook.common.references.SharedReference;
import kotlin.Metadata;

/* compiled from: CloseableReferenceLeakTracker.kt */
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0003\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001:\u0001\u000eJ\"\u0010\u0002\u001a\u00020\u00032\u000e\u0010\u0004\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007H&J\u0012\u0010\b\u001a\u00020\u00032\b\u0010\t\u001a\u0004\u0018\u00010\nH&R\u0012\u0010\u000b\u001a\u00020\fX¦\u0004¢\u0006\u0006\u001a\u0004\b\u000b\u0010\r¨\u0006\u000f"}, d2 = {"Lcom/facebook/imagepipeline/debug/CloseableReferenceLeakTracker;", "", "trackCloseableReferenceLeak", "", "reference", "Lcom/facebook/common/references/SharedReference;", "stacktrace", "", "setListener", "listener", "Lcom/facebook/imagepipeline/debug/CloseableReferenceLeakTracker$Listener;", "isSet", "", "()Z", "Listener", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface CloseableReferenceLeakTracker {

    /* compiled from: CloseableReferenceLeakTracker.kt */
    @Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0003\n\u0000\bf\u0018\u00002\u00020\u0001J\"\u0010\u0002\u001a\u00020\u00032\u000e\u0010\u0004\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007H&¨\u0006\b"}, d2 = {"Lcom/facebook/imagepipeline/debug/CloseableReferenceLeakTracker$Listener;", "", "onCloseableReferenceLeak", "", "reference", "Lcom/facebook/common/references/SharedReference;", "stacktrace", "", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface Listener {
        void onCloseableReferenceLeak(SharedReference<Object> reference, Throwable stacktrace);
    }

    boolean isSet();

    void setListener(Listener listener);

    void trackCloseableReferenceLeak(SharedReference<Object> reference, Throwable stacktrace);
}
