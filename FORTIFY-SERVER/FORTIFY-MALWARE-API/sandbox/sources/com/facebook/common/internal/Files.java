package com.facebook.common.internal;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public class Files {
    private Files() {
    }

    static byte[] readFile(InputStream inputStream, long j) throws IOException {
        if (j > 2147483647L) {
            throw new OutOfMemoryError("file is too large to fit in a byte array: " + j + " bytes");
        }
        if (j == 0) {
            return ByteStreams.toByteArray(inputStream);
        }
        return ByteStreams.toByteArray(inputStream, (int) j);
    }

    public static byte[] toByteArray(File file) throws Throwable {
        FileInputStream fileInputStream = null;
        try {
            FileInputStream fileInputStream2 = new FileInputStream(file);
            try {
                byte[] file2 = readFile(fileInputStream2, fileInputStream2.getChannel().size());
                fileInputStream2.close();
                return file2;
            } catch (Throwable th) {
                th = th;
                fileInputStream = fileInputStream2;
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }
}
