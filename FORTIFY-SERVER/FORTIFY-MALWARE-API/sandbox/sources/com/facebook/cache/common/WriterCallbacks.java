package com.facebook.cache.common;

import com.facebook.common.internal.ByteStreams;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes.dex */
public class WriterCallbacks {
    public static WriterCallback from(final InputStream inputStream) {
        return new WriterCallback() { // from class: com.facebook.cache.common.WriterCallbacks.1
            @Override // com.facebook.cache.common.WriterCallback
            public void write(OutputStream outputStream) throws IOException {
                ByteStreams.copy(inputStream, outputStream);
            }
        };
    }

    public static WriterCallback from(final byte[] bArr) {
        return new WriterCallback() { // from class: com.facebook.cache.common.WriterCallbacks.2
            @Override // com.facebook.cache.common.WriterCallback
            public void write(OutputStream outputStream) throws IOException {
                outputStream.write(bArr);
            }
        };
    }
}
