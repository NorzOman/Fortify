package com.facebook.common.memory;

import androidx.core.util.Pools;
import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public class DecodeBufferHelper implements Pools.Pool<ByteBuffer> {
    private static final int DEFAULT_DECODE_BUFFER_SIZE = 16384;
    public static final DecodeBufferHelper INSTANCE = new DecodeBufferHelper();
    private static int sRecommendedDecodeBufferSize = 16384;
    private static final ThreadLocal<ByteBuffer> sBuffer = new ThreadLocal<ByteBuffer>() { // from class: com.facebook.common.memory.DecodeBufferHelper.1
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // java.lang.ThreadLocal
        public ByteBuffer initialValue() {
            return ByteBuffer.allocate(DecodeBufferHelper.sRecommendedDecodeBufferSize);
        }
    };

    @Override // androidx.core.util.Pools.Pool
    public boolean release(ByteBuffer byteBuffer) {
        return true;
    }

    public static int getRecommendedDecodeBufferSize() {
        return sRecommendedDecodeBufferSize;
    }

    public static void setRecommendedDecodeBufferSize(int i) {
        sRecommendedDecodeBufferSize = i;
    }

    @Override // androidx.core.util.Pools.Pool
    public ByteBuffer acquire() {
        return sBuffer.get();
    }
}
