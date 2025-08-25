package com.facebook.imagepipeline.core;

import android.util.Log;
import com.facebook.common.logging.FLog;
import com.facebook.common.references.CloseableReference;
import com.facebook.common.references.ResourceReleaser;
import com.facebook.common.references.SharedReference;
import com.facebook.imagepipeline.debug.CloseableReferenceLeakTracker;
import java.io.Closeable;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class CloseableReferenceFactory {
    private final CloseableReference.LeakHandler mLeakHandler;

    public CloseableReferenceFactory(final CloseableReferenceLeakTracker closeableReferenceLeakTracker) {
        this.mLeakHandler = new CloseableReference.LeakHandler() { // from class: com.facebook.imagepipeline.core.CloseableReferenceFactory.1
            @Override // com.facebook.common.references.CloseableReference.LeakHandler
            public void reportLeak(SharedReference<Object> sharedReference, @Nullable Throwable th) {
                closeableReferenceLeakTracker.trackCloseableReferenceLeak(sharedReference, th);
                Object obj = sharedReference.get();
                FLog.w("Fresco", "Finalized without closing: %x %x (type = %s).\nStack:\n%s", Integer.valueOf(System.identityHashCode(this)), Integer.valueOf(System.identityHashCode(sharedReference)), obj != null ? obj.getClass().getName() : "<value is null>", CloseableReferenceFactory.getStackTraceString(th));
            }

            @Override // com.facebook.common.references.CloseableReference.LeakHandler
            public boolean requiresStacktrace() {
                return closeableReferenceLeakTracker.isSet();
            }
        };
    }

    public <U extends Closeable> CloseableReference<U> create(@Nullable U u) {
        return CloseableReference.of(u, this.mLeakHandler);
    }

    public <T> CloseableReference<T> create(T t, ResourceReleaser<T> resourceReleaser) {
        return CloseableReference.of(t, resourceReleaser, this.mLeakHandler);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String getStackTraceString(@Nullable Throwable th) {
        if (th == null) {
            return "";
        }
        return Log.getStackTraceString(th);
    }
}
