package com.facebook.imageformat;

import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DefaultImageFormats.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010 \n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0005H\u0007J\u0010\u0010\u0016\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0005H\u0007R\u0010\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0006\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0007\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\b\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\t\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\n\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u000b\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\f\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\r\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u000e\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u000f\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0010\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0011\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0010\u0010\u0012\u001a\u00020\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0016\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00050\u00188\u0006X\u0087\u0004¢\u0006\u0002\n\u0000¨\u0006\u0019"}, d2 = {"Lcom/facebook/imageformat/DefaultImageFormats;", "", "<init>", "()V", "JPEG", "Lcom/facebook/imageformat/ImageFormat;", "PNG", "GIF", "BMP", "ICO", "WEBP_SIMPLE", "WEBP_LOSSLESS", "WEBP_EXTENDED", "WEBP_EXTENDED_WITH_ALPHA", "WEBP_ANIMATED", "HEIF", "DNG", "BINARY_XML", "AVIF", "isWebpFormat", "", "imageFormat", "isStaticWebpFormat", "defaultFormats", "", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DefaultImageFormats {
    public static final ImageFormat AVIF;
    public static final ImageFormat BINARY_XML;
    public static final ImageFormat BMP;
    public static final ImageFormat DNG;
    public static final ImageFormat GIF;
    public static final ImageFormat HEIF;
    public static final ImageFormat ICO;
    public static final DefaultImageFormats INSTANCE = new DefaultImageFormats();
    public static final ImageFormat JPEG;
    public static final ImageFormat PNG;
    public static final ImageFormat WEBP_ANIMATED;
    public static final ImageFormat WEBP_EXTENDED;
    public static final ImageFormat WEBP_EXTENDED_WITH_ALPHA;
    public static final ImageFormat WEBP_LOSSLESS;
    public static final ImageFormat WEBP_SIMPLE;
    public static final List<ImageFormat> defaultFormats;

    private DefaultImageFormats() {
    }

    static {
        ImageFormat imageFormat = new ImageFormat("JPEG", "jpeg");
        JPEG = imageFormat;
        ImageFormat imageFormat2 = new ImageFormat("PNG", "png");
        PNG = imageFormat2;
        ImageFormat imageFormat3 = new ImageFormat("GIF", "gif");
        GIF = imageFormat3;
        ImageFormat imageFormat4 = new ImageFormat("BMP", "bmp");
        BMP = imageFormat4;
        ImageFormat imageFormat5 = new ImageFormat("ICO", "ico");
        ICO = imageFormat5;
        ImageFormat imageFormat6 = new ImageFormat("WEBP_SIMPLE", "webp");
        WEBP_SIMPLE = imageFormat6;
        ImageFormat imageFormat7 = new ImageFormat("WEBP_LOSSLESS", "webp");
        WEBP_LOSSLESS = imageFormat7;
        ImageFormat imageFormat8 = new ImageFormat("WEBP_EXTENDED", "webp");
        WEBP_EXTENDED = imageFormat8;
        ImageFormat imageFormat9 = new ImageFormat("WEBP_EXTENDED_WITH_ALPHA", "webp");
        WEBP_EXTENDED_WITH_ALPHA = imageFormat9;
        ImageFormat imageFormat10 = new ImageFormat("WEBP_ANIMATED", "webp");
        WEBP_ANIMATED = imageFormat10;
        ImageFormat imageFormat11 = new ImageFormat("HEIF", "heif");
        HEIF = imageFormat11;
        DNG = new ImageFormat("DNG", "dng");
        ImageFormat imageFormat12 = new ImageFormat("BINARY_XML", "xml");
        BINARY_XML = imageFormat12;
        ImageFormat imageFormat13 = new ImageFormat("AVIF", "avif");
        AVIF = imageFormat13;
        defaultFormats = CollectionsKt.listOf((Object[]) new ImageFormat[]{imageFormat, imageFormat2, imageFormat3, imageFormat4, imageFormat5, imageFormat6, imageFormat7, imageFormat8, imageFormat9, imageFormat10, imageFormat11, imageFormat12, imageFormat13});
    }

    @JvmStatic
    public static final boolean isWebpFormat(ImageFormat imageFormat) {
        Intrinsics.checkNotNullParameter(imageFormat, "imageFormat");
        return isStaticWebpFormat(imageFormat) || imageFormat == WEBP_ANIMATED;
    }

    @JvmStatic
    public static final boolean isStaticWebpFormat(ImageFormat imageFormat) {
        Intrinsics.checkNotNullParameter(imageFormat, "imageFormat");
        return imageFormat == WEBP_SIMPLE || imageFormat == WEBP_LOSSLESS || imageFormat == WEBP_EXTENDED || imageFormat == WEBP_EXTENDED_WITH_ALPHA;
    }
}
