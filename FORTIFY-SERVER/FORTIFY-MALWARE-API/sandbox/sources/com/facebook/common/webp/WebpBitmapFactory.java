package com.facebook.common.webp;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Rect;
import java.io.FileDescriptor;
import java.io.InputStream;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public interface WebpBitmapFactory {

    public interface WebpErrorLogger {
        void onWebpErrorLog(String str, @Nullable String str2);
    }

    @Nullable
    Bitmap decodeByteArray(byte[] bArr, int i, int i2, @Nullable BitmapFactory.Options options);

    @Nullable
    Bitmap decodeFile(String str, @Nullable BitmapFactory.Options options);

    @Nullable
    Bitmap decodeFileDescriptor(FileDescriptor fileDescriptor, @Nullable Rect rect, @Nullable BitmapFactory.Options options);

    @Nullable
    Bitmap decodeStream(InputStream inputStream, @Nullable Rect rect, @Nullable BitmapFactory.Options options);

    void setBitmapCreator(BitmapCreator bitmapCreator);

    void setWebpErrorLogger(WebpErrorLogger webpErrorLogger);
}
