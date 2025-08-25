package com.facebook.imagepipeline.memory;

import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class NoOpPoolStatsTracker implements PoolStatsTracker {

    @Nullable
    private static NoOpPoolStatsTracker sInstance;

    @Override // com.facebook.imagepipeline.memory.PoolStatsTracker
    public void onAlloc(int i) {
    }

    @Override // com.facebook.imagepipeline.memory.PoolStatsTracker
    public void onFree(int i) {
    }

    @Override // com.facebook.imagepipeline.memory.PoolStatsTracker
    public void onHardCapReached() {
    }

    @Override // com.facebook.imagepipeline.memory.PoolStatsTracker
    public void onSoftCapReached() {
    }

    @Override // com.facebook.imagepipeline.memory.PoolStatsTracker
    public void onValueRelease(int i) {
    }

    @Override // com.facebook.imagepipeline.memory.PoolStatsTracker
    public void onValueReuse(int i) {
    }

    @Override // com.facebook.imagepipeline.memory.PoolStatsTracker
    public void setBasePool(BasePool basePool) {
    }

    private NoOpPoolStatsTracker() {
    }

    public static synchronized NoOpPoolStatsTracker getInstance() {
        if (sInstance == null) {
            sInstance = new NoOpPoolStatsTracker();
        }
        return sInstance;
    }
}
