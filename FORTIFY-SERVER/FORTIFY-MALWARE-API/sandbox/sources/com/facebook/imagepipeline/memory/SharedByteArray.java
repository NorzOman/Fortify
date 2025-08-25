package com.facebook.imagepipeline.memory;

import com.facebook.common.internal.Preconditions;
import com.facebook.common.internal.Throwables;
import com.facebook.common.memory.MemoryTrimType;
import com.facebook.common.memory.MemoryTrimmable;
import com.facebook.common.memory.MemoryTrimmableRegistry;
import com.facebook.common.references.CloseableReference;
import com.facebook.common.references.OOMSoftReference;
import com.facebook.common.references.ResourceReleaser;
import java.util.concurrent.Semaphore;

/* loaded from: classes.dex */
public class SharedByteArray implements MemoryTrimmable {
    final OOMSoftReference<byte[]> mByteArraySoftRef;
    final int mMaxByteArraySize;
    final int mMinByteArraySize;
    private final ResourceReleaser<byte[]> mResourceReleaser;
    final Semaphore mSemaphore;

    public SharedByteArray(MemoryTrimmableRegistry memoryTrimmableRegistry, PoolParams poolParams) {
        Preconditions.checkNotNull(memoryTrimmableRegistry);
        Preconditions.checkArgument(Boolean.valueOf(poolParams.minBucketSize > 0));
        Preconditions.checkArgument(Boolean.valueOf(poolParams.maxBucketSize >= poolParams.minBucketSize));
        this.mMaxByteArraySize = poolParams.maxBucketSize;
        this.mMinByteArraySize = poolParams.minBucketSize;
        this.mByteArraySoftRef = new OOMSoftReference<>();
        this.mSemaphore = new Semaphore(1);
        this.mResourceReleaser = new ResourceReleaser<byte[]>() { // from class: com.facebook.imagepipeline.memory.SharedByteArray.1
            @Override // com.facebook.common.references.ResourceReleaser
            public void release(byte[] bArr) {
                SharedByteArray.this.mSemaphore.release();
            }
        };
        memoryTrimmableRegistry.registerMemoryTrimmable(this);
    }

    public CloseableReference<byte[]> get(int i) {
        Preconditions.checkArgument(i > 0, "Size must be greater than zero");
        Preconditions.checkArgument(i <= this.mMaxByteArraySize, "Requested size is too big");
        this.mSemaphore.acquireUninterruptibly();
        try {
            return CloseableReference.of(getByteArray(i), this.mResourceReleaser);
        } catch (Throwable th) {
            this.mSemaphore.release();
            throw Throwables.propagate(th);
        }
    }

    private byte[] getByteArray(int i) {
        int bucketedSize = getBucketedSize(i);
        byte[] bArr = this.mByteArraySoftRef.get();
        return (bArr == null || bArr.length < bucketedSize) ? allocateByteArray(bucketedSize) : bArr;
    }

    @Override // com.facebook.common.memory.MemoryTrimmable
    public void trim(MemoryTrimType memoryTrimType) {
        if (this.mSemaphore.tryAcquire()) {
            try {
                this.mByteArraySoftRef.clear();
            } finally {
                this.mSemaphore.release();
            }
        }
    }

    int getBucketedSize(int i) {
        return Integer.highestOneBit(Math.max(i, this.mMinByteArraySize) - 1) * 2;
    }

    private synchronized byte[] allocateByteArray(int i) {
        byte[] bArr;
        this.mByteArraySoftRef.clear();
        bArr = new byte[i];
        this.mByteArraySoftRef.set(bArr);
        return bArr;
    }
}
