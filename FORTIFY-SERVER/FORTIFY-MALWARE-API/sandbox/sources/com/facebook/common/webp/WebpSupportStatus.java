package com.facebook.common.webp;

import java.io.UnsupportedEncodingException;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class WebpSupportStatus {
    private static final int EXTENDED_WEBP_HEADER_LENGTH = 21;
    private static final int SIMPLE_WEBP_HEADER_LENGTH = 20;
    private static final String VP8X_WEBP_BASE64 = "UklGRkoAAABXRUJQVlA4WAoAAAAQAAAAAAAAAAAAQUxQSAwAAAARBxAR/Q9ERP8DAABWUDggGAAAABQBAJ0BKgEAAQAAAP4AAA3AAP7mtQAAAA==";
    public static final boolean sIsSimpleWebpSupported = true;
    public static final boolean sIsExtendedWebpSupported = isExtendedWebpSupported();

    @Nullable
    public static WebpBitmapFactory sWebpBitmapFactory = null;
    private static boolean sWebpLibraryChecked = false;
    private static final byte[] WEBP_RIFF_BYTES = asciiBytes("RIFF");
    private static final byte[] WEBP_NAME_BYTES = asciiBytes("WEBP");
    private static final byte[] WEBP_VP8_BYTES = asciiBytes("VP8 ");
    private static final byte[] WEBP_VP8L_BYTES = asciiBytes("VP8L");
    private static final byte[] WEBP_VP8X_BYTES = asciiBytes("VP8X");

    private static boolean isExtendedWebpSupported() {
        return true;
    }

    @Nullable
    public static WebpBitmapFactory loadWebpBitmapFactoryIfExists() {
        WebpBitmapFactory webpBitmapFactory;
        if (sWebpLibraryChecked) {
            return sWebpBitmapFactory;
        }
        try {
            webpBitmapFactory = (WebpBitmapFactory) Class.forName("com.facebook.webpsupport.WebpBitmapFactoryImpl").newInstance();
        } catch (Throwable unused) {
            webpBitmapFactory = null;
        }
        sWebpLibraryChecked = true;
        return webpBitmapFactory;
    }

    private static byte[] asciiBytes(String str) {
        try {
            return str.getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("ASCII not found!", e);
        }
    }

    public static boolean isWebpSupportedByPlatform(byte[] bArr, int i, int i2) {
        if (isSimpleWebpHeader(bArr, i)) {
            return sIsSimpleWebpSupported;
        }
        if (isLosslessWebpHeader(bArr, i)) {
            return sIsExtendedWebpSupported;
        }
        if (!isExtendedWebpHeader(bArr, i, i2) || isAnimatedWebpHeader(bArr, i)) {
            return false;
        }
        return sIsExtendedWebpSupported;
    }

    public static boolean isAnimatedWebpHeader(byte[] bArr, int i) {
        return matchBytePattern(bArr, i + 12, WEBP_VP8X_BYTES) && ((bArr[i + 20] & 2) == 2);
    }

    public static boolean isSimpleWebpHeader(byte[] bArr, int i) {
        return matchBytePattern(bArr, i + 12, WEBP_VP8_BYTES);
    }

    public static boolean isLosslessWebpHeader(byte[] bArr, int i) {
        return matchBytePattern(bArr, i + 12, WEBP_VP8L_BYTES);
    }

    public static boolean isExtendedWebpHeader(byte[] bArr, int i, int i2) {
        return i2 >= 21 && matchBytePattern(bArr, i + 12, WEBP_VP8X_BYTES);
    }

    public static boolean isExtendedWebpHeaderWithAlpha(byte[] bArr, int i) {
        return matchBytePattern(bArr, i + 12, WEBP_VP8X_BYTES) && ((bArr[i + 20] & 16) == 16);
    }

    public static boolean isWebpHeader(byte[] bArr, int i, int i2) {
        return i2 >= 20 && matchBytePattern(bArr, i, WEBP_RIFF_BYTES) && matchBytePattern(bArr, i + 8, WEBP_NAME_BYTES);
    }

    private static boolean matchBytePattern(byte[] bArr, int i, byte[] bArr2) {
        if (bArr2 == null || bArr == null || bArr2.length + i > bArr.length) {
            return false;
        }
        for (int i2 = 0; i2 < bArr2.length; i2++) {
            if (bArr[i2 + i] != bArr2[i2]) {
                return false;
            }
        }
        return true;
    }
}
