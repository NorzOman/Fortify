package com.facebook.drawee.components;

import android.os.Handler;
import android.os.Looper;
import com.facebook.drawee.components.DeferredReleaser;
import java.util.ArrayList;

/* loaded from: classes.dex */
class DeferredReleaserConcurrentImpl extends DeferredReleaser {
    private final Object mLock = new Object();
    private final Runnable releaseRunnable = new Runnable() { // from class: com.facebook.drawee.components.DeferredReleaserConcurrentImpl.1
        @Override // java.lang.Runnable
        public void run() {
            synchronized (DeferredReleaserConcurrentImpl.this.mLock) {
                ArrayList arrayList = DeferredReleaserConcurrentImpl.this.mTempList;
                DeferredReleaserConcurrentImpl deferredReleaserConcurrentImpl = DeferredReleaserConcurrentImpl.this;
                deferredReleaserConcurrentImpl.mTempList = deferredReleaserConcurrentImpl.mPendingReleasables;
                DeferredReleaserConcurrentImpl.this.mPendingReleasables = arrayList;
            }
            int size = DeferredReleaserConcurrentImpl.this.mTempList.size();
            for (int i = 0; i < size; i++) {
                ((DeferredReleaser.Releasable) DeferredReleaserConcurrentImpl.this.mTempList.get(i)).release();
            }
            DeferredReleaserConcurrentImpl.this.mTempList.clear();
        }
    };
    private ArrayList<DeferredReleaser.Releasable> mPendingReleasables = new ArrayList<>();
    private ArrayList<DeferredReleaser.Releasable> mTempList = new ArrayList<>();
    private final Handler mUiHandler = new Handler(Looper.getMainLooper());

    @Override // com.facebook.drawee.components.DeferredReleaser
    public void scheduleDeferredRelease(DeferredReleaser.Releasable releasable) {
        if (!isOnUiThread()) {
            releasable.release();
            return;
        }
        synchronized (this.mLock) {
            if (this.mPendingReleasables.contains(releasable)) {
                return;
            }
            this.mPendingReleasables.add(releasable);
            boolean z = true;
            if (this.mPendingReleasables.size() != 1) {
                z = false;
            }
            if (z) {
                this.mUiHandler.post(this.releaseRunnable);
            }
        }
    }

    @Override // com.facebook.drawee.components.DeferredReleaser
    public void cancelDeferredRelease(DeferredReleaser.Releasable releasable) {
        synchronized (this.mLock) {
            this.mPendingReleasables.remove(releasable);
        }
    }
}
