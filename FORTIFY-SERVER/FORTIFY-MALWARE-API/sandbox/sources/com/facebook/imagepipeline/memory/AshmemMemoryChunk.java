package com.facebook.imagepipeline.memory;

import android.os.SharedMemory;
import android.system.ErrnoException;
import android.util.Log;
import com.facebook.common.internal.Preconditions;
import java.io.Closeable;
import java.nio.ByteBuffer;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class AshmemMemoryChunk implements MemoryChunk, Closeable {
    private static final String TAG = "AshmemMemoryChunk";

    @Nullable
    private ByteBuffer mByteBuffer;
    private final long mId;

    @Nullable
    private SharedMemory mSharedMemory;

    public AshmemMemoryChunk(int i) throws ErrnoException {
        Preconditions.checkArgument(Boolean.valueOf(i > 0));
        try {
            SharedMemory sharedMemoryCreate = SharedMemory.create(TAG, i);
            this.mSharedMemory = sharedMemoryCreate;
            this.mByteBuffer = sharedMemoryCreate.mapReadWrite();
            this.mId = System.identityHashCode(this);
        } catch (ErrnoException e) {
            throw new RuntimeException("Fail to create AshmemMemory", e);
        }
    }

    public AshmemMemoryChunk() {
        this.mSharedMemory = null;
        this.mByteBuffer = null;
        this.mId = System.identityHashCode(this);
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        if (!isClosed()) {
            SharedMemory sharedMemory = this.mSharedMemory;
            if (sharedMemory != null) {
                sharedMemory.close();
            }
            ByteBuffer byteBuffer = this.mByteBuffer;
            if (byteBuffer != null) {
                SharedMemory.unmap(byteBuffer);
            }
            this.mByteBuffer = null;
            this.mSharedMemory = null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x000c  */
    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized boolean isClosed() {
        /*
            r1 = this;
            monitor-enter(r1)
            java.nio.ByteBuffer r0 = r1.mByteBuffer     // Catch: java.lang.Throwable -> Lf
            if (r0 == 0) goto Lc
            android.os.SharedMemory r0 = r1.mSharedMemory     // Catch: java.lang.Throwable -> Lf
            if (r0 != 0) goto La
            goto Lc
        La:
            r0 = 0
            goto Ld
        Lc:
            r0 = 1
        Ld:
            monitor-exit(r1)
            return r0
        Lf:
            r0 = move-exception
            monitor-exit(r1)     // Catch: java.lang.Throwable -> Lf
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.imagepipeline.memory.AshmemMemoryChunk.isClosed():boolean");
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    public int getSize() {
        Preconditions.checkNotNull(this.mSharedMemory);
        return this.mSharedMemory.getSize();
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    public synchronized int write(int i, byte[] bArr, int i2, int i3) {
        int iAdjustByteCount;
        Preconditions.checkNotNull(bArr);
        Preconditions.checkNotNull(this.mByteBuffer);
        iAdjustByteCount = MemoryChunkUtil.adjustByteCount(i, i3, getSize());
        MemoryChunkUtil.checkBounds(i, bArr.length, i2, iAdjustByteCount, getSize());
        this.mByteBuffer.position(i);
        this.mByteBuffer.put(bArr, i2, iAdjustByteCount);
        return iAdjustByteCount;
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    public synchronized int read(int i, byte[] bArr, int i2, int i3) {
        int iAdjustByteCount;
        Preconditions.checkNotNull(bArr);
        Preconditions.checkNotNull(this.mByteBuffer);
        iAdjustByteCount = MemoryChunkUtil.adjustByteCount(i, i3, getSize());
        MemoryChunkUtil.checkBounds(i, bArr.length, i2, iAdjustByteCount, getSize());
        this.mByteBuffer.position(i);
        this.mByteBuffer.get(bArr, i2, iAdjustByteCount);
        return iAdjustByteCount;
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    public synchronized byte read(int i) {
        boolean z = true;
        Preconditions.checkState(!isClosed());
        Preconditions.checkArgument(Boolean.valueOf(i >= 0));
        if (i >= getSize()) {
            z = false;
        }
        Preconditions.checkArgument(Boolean.valueOf(z));
        Preconditions.checkNotNull(this.mByteBuffer);
        return this.mByteBuffer.get(i);
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    public long getNativePtr() {
        throw new UnsupportedOperationException("Cannot get the pointer of an  AshmemMemoryChunk");
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    @Nullable
    public ByteBuffer getByteBuffer() {
        return this.mByteBuffer;
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    public long getUniqueId() {
        return this.mId;
    }

    @Override // com.facebook.imagepipeline.memory.MemoryChunk
    public void copy(int i, MemoryChunk memoryChunk, int i2, int i3) {
        Preconditions.checkNotNull(memoryChunk);
        if (memoryChunk.getUniqueId() == getUniqueId()) {
            Log.w(TAG, "Copying from AshmemMemoryChunk " + Long.toHexString(getUniqueId()) + " to AshmemMemoryChunk " + Long.toHexString(memoryChunk.getUniqueId()) + " which are the same ");
            Preconditions.checkArgument(false);
        }
        if (memoryChunk.getUniqueId() < getUniqueId()) {
            synchronized (memoryChunk) {
                synchronized (this) {
                    doCopy(i, memoryChunk, i2, i3);
                }
            }
        } else {
            synchronized (this) {
                synchronized (memoryChunk) {
                    doCopy(i, memoryChunk, i2, i3);
                }
            }
        }
    }

    private void doCopy(int i, MemoryChunk memoryChunk, int i2, int i3) {
        if (!(memoryChunk instanceof AshmemMemoryChunk)) {
            throw new IllegalArgumentException("Cannot copy two incompatible MemoryChunks");
        }
        Preconditions.checkState(!isClosed());
        Preconditions.checkState(!memoryChunk.isClosed());
        Preconditions.checkNotNull(this.mByteBuffer);
        Preconditions.checkNotNull(memoryChunk.getByteBuffer());
        MemoryChunkUtil.checkBounds(i, memoryChunk.getSize(), i2, i3, getSize());
        this.mByteBuffer.position(i);
        memoryChunk.getByteBuffer().position(i2);
        byte[] bArr = new byte[i3];
        this.mByteBuffer.get(bArr, 0, i3);
        memoryChunk.getByteBuffer().put(bArr, 0, i3);
    }
}
