package com.facebook.common.memory;

import com.facebook.common.internal.Preconditions;
import java.io.InputStream;
import kotlin.UByte;

/* loaded from: classes.dex */
public class PooledByteBufferInputStream extends InputStream {
    int mMark;
    int mOffset;
    final PooledByteBuffer mPooledByteBuffer;

    @Override // java.io.InputStream
    public boolean markSupported() {
        return true;
    }

    public PooledByteBufferInputStream(PooledByteBuffer pooledByteBuffer) {
        Preconditions.checkArgument(Boolean.valueOf(!pooledByteBuffer.isClosed()));
        this.mPooledByteBuffer = (PooledByteBuffer) Preconditions.checkNotNull(pooledByteBuffer);
        this.mOffset = 0;
        this.mMark = 0;
    }

    @Override // java.io.InputStream
    public int available() {
        return this.mPooledByteBuffer.size() - this.mOffset;
    }

    @Override // java.io.InputStream
    public void mark(int i) {
        this.mMark = this.mOffset;
    }

    @Override // java.io.InputStream
    public int read() {
        if (available() <= 0) {
            return -1;
        }
        PooledByteBuffer pooledByteBuffer = this.mPooledByteBuffer;
        int i = this.mOffset;
        this.mOffset = i + 1;
        return pooledByteBuffer.read(i) & UByte.MAX_VALUE;
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr) {
        return read(bArr, 0, bArr.length);
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i, int i2) {
        if (i < 0 || i2 < 0 || i + i2 > bArr.length) {
            throw new ArrayIndexOutOfBoundsException("length=" + bArr.length + "; regionStart=" + i + "; regionLength=" + i2);
        }
        int iAvailable = available();
        if (iAvailable <= 0) {
            return -1;
        }
        if (i2 <= 0) {
            return 0;
        }
        int iMin = Math.min(iAvailable, i2);
        this.mPooledByteBuffer.read(this.mOffset, bArr, i, iMin);
        this.mOffset += iMin;
        return iMin;
    }

    @Override // java.io.InputStream
    public void reset() {
        this.mOffset = this.mMark;
    }

    @Override // java.io.InputStream
    public long skip(long j) {
        Preconditions.checkArgument(Boolean.valueOf(j >= 0));
        int iMin = Math.min((int) j, available());
        this.mOffset += iMin;
        return iMin;
    }
}
