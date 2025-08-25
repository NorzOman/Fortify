package com.facebook.imagepipeline.image;

import com.facebook.common.logging.FLog;

/* loaded from: classes.dex */
public abstract class DefaultCloseableImage extends BaseCloseableImage {
    private static final String TAG = "CloseableImage";

    protected void finalize() throws Throwable {
        if (isClosed()) {
            return;
        }
        FLog.w(TAG, "finalize: %s %x still open.", getClass().getSimpleName(), Integer.valueOf(System.identityHashCode(this)));
        try {
            close();
        } finally {
            super.finalize();
        }
    }
}
