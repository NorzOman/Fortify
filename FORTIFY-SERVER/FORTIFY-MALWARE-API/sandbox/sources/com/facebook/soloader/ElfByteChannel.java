package com.facebook.soloader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;

/* loaded from: classes.dex */
public interface ElfByteChannel extends ByteChannel {
    long position() throws IOException;

    ElfByteChannel position(long j) throws IOException;

    @Override // java.nio.channels.ReadableByteChannel
    int read(ByteBuffer byteBuffer) throws IOException;

    int read(ByteBuffer byteBuffer, long j) throws IOException;

    long size() throws IOException;

    ElfByteChannel truncate(long j) throws IOException;

    @Override // java.nio.channels.WritableByteChannel
    int write(ByteBuffer byteBuffer) throws IOException;
}
