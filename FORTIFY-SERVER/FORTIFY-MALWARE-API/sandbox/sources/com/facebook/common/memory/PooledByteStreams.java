package com.facebook.common.memory;

import com.facebook.common.internal.Preconditions;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes.dex */
public class PooledByteStreams {
    private static final int DEFAULT_TEMP_BUF_SIZE = 16384;
    private final ByteArrayPool mByteArrayPool;
    private final int mTempBufSize;

    public PooledByteStreams(ByteArrayPool byteArrayPool) {
        this(byteArrayPool, 16384);
    }

    public PooledByteStreams(ByteArrayPool byteArrayPool, int i) {
        Preconditions.checkArgument(Boolean.valueOf(i > 0));
        this.mTempBufSize = i;
        this.mByteArrayPool = byteArrayPool;
    }

    public long copy(InputStream inputStream, OutputStream outputStream) throws IOException {
        byte[] bArr = this.mByteArrayPool.get(this.mTempBufSize);
        long j = 0;
        while (true) {
            try {
                int i = inputStream.read(bArr, 0, this.mTempBufSize);
                if (i == -1) {
                    return j;
                }
                outputStream.write(bArr, 0, i);
                j += i;
            } finally {
                this.mByteArrayPool.release(bArr);
            }
        }
    }

    public long copy(InputStream inputStream, OutputStream outputStream, long j) throws IOException {
        long j2 = 0;
        Preconditions.checkState(j > 0);
        byte[] bArr = this.mByteArrayPool.get(this.mTempBufSize);
        while (j2 < j) {
            try {
                int i = inputStream.read(bArr, 0, (int) Math.min(this.mTempBufSize, j - j2));
                if (i == -1) {
                    break;
                }
                outputStream.write(bArr, 0, i);
                j2 += i;
            } finally {
                this.mByteArrayPool.release(bArr);
            }
        }
        return j2;
    }
}
