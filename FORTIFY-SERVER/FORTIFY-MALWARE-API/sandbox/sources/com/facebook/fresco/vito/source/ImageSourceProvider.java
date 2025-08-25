package com.facebook.fresco.vito.source;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.MapsKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ImageSourceProvider.kt */
@Metadata(d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010$\n\u0002\b\u0003\n\u0002\u0010\u0011\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\b\u0010\f\u001a\u00020\rH\u0007J*\u0010\u000e\u001a\u00020\r2\b\u0010\u000f\u001a\u0004\u0018\u00010\u00072\u0016\b\u0002\u0010\u0010\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u0011H\u0007J*\u0010\u000e\u001a\u00020\r2\b\u0010\u0012\u001a\u0004\u0018\u00010\u00062\u0016\b\u0002\u0010\u0010\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u0011H\u0007J!\u0010\u0013\u001a\u00020\r2\u0012\u0010\u0014\u001a\n\u0012\u0006\b\u0001\u0012\u00020\r0\u0015\"\u00020\rH\u0007¢\u0006\u0002\u0010\u0016J\u0018\u0010\u0017\u001a\u00020\r2\u0006\u0010\u0018\u001a\u00020\r2\u0006\u0010\u0019\u001a\u00020\rH\u0007J0\u0010\u0017\u001a\u00020\r2\u0006\u0010\u0018\u001a\u00020\r2\u0006\u0010\u0019\u001a\u00020\r2\u0016\b\u0002\u0010\u0010\u001a\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u0011H\u0007J\u001c\u0010\u0017\u001a\u00020\r2\b\u0010\u001a\u001a\u0004\u0018\u00010\u00072\b\u0010\u001b\u001a\u0004\u0018\u00010\u0007H\u0007J\u0010\u0010\u001c\u001a\u00020\r2\u0006\u0010\u001c\u001a\u00020\u001dH\u0007J\u0010\u0010\u001e\u001a\u00020\r2\u0006\u0010\u001e\u001a\u00020\u001fH\u0007R&\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00070\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\b\u0010\t\"\u0004\b\n\u0010\u000b¨\u0006 "}, d2 = {"Lcom/facebook/fresco/vito/source/ImageSourceProvider;", "", "<init>", "()V", "uriParser", "Lkotlin/Function1;", "", "Landroid/net/Uri;", "getUriParser", "()Lkotlin/jvm/functions/Function1;", "setUriParser", "(Lkotlin/jvm/functions/Function1;)V", "emptySource", "Lcom/facebook/fresco/vito/source/ImageSource;", "forUri", "uri", "extras", "", "uriString", "firstAvailable", "imageSources", "", "([Lcom/facebook/fresco/vito/source/ImageSource;)Lcom/facebook/fresco/vito/source/ImageSource;", "increasingQuality", "lowResImageSource", "highResImageSource", "lowResImageUri", "highResImageUri", "bitmap", "Landroid/graphics/Bitmap;", "drawable", "Landroid/graphics/drawable/Drawable;", "source_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ImageSourceProvider {
    public static final ImageSourceProvider INSTANCE = new ImageSourceProvider();
    private static Function1<? super String, ? extends Uri> uriParser = new Function1() { // from class: com.facebook.fresco.vito.source.ImageSourceProvider$$ExternalSyntheticLambda0
        @Override // kotlin.jvm.functions.Function1
        public final Object invoke(Object obj) {
            return ImageSourceProvider.uriParser$lambda$0((String) obj);
        }
    };

    @JvmStatic
    public static final ImageSource forUri(Uri uri) {
        return forUri$default(uri, (Map) null, 2, (Object) null);
    }

    @JvmStatic
    public static final ImageSource forUri(String str) {
        return forUri$default(str, (Map) null, 2, (Object) null);
    }

    private ImageSourceProvider() {
    }

    public final Function1<String, Uri> getUriParser() {
        return uriParser;
    }

    public final void setUriParser(Function1<? super String, ? extends Uri> function1) {
        Intrinsics.checkNotNullParameter(function1, "<set-?>");
        uriParser = function1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Uri uriParser$lambda$0(String it) {
        Intrinsics.checkNotNullParameter(it, "it");
        Uri uri = Uri.parse(it);
        Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
        return uri;
    }

    @JvmStatic
    public static final ImageSource emptySource() {
        return EmptyImageSource.INSTANCE;
    }

    public static /* synthetic */ ImageSource forUri$default(Uri uri, Map map, int i, Object obj) {
        if ((i & 2) != 0) {
            map = null;
        }
        return forUri(uri, (Map<String, ? extends Object>) map);
    }

    @JvmStatic
    public static final ImageSource forUri(Uri uri, Map<String, ? extends Object> extras) {
        if (uri == null) {
            return emptySource();
        }
        Map mapCreateMapBuilder = MapsKt.createMapBuilder();
        if (extras != null) {
            mapCreateMapBuilder.putAll(extras);
        }
        mapCreateMapBuilder.put("uri_source", uri);
        return new SingleImageSourceImpl(uri, MapsKt.build(mapCreateMapBuilder));
    }

    public static /* synthetic */ ImageSource forUri$default(String str, Map map, int i, Object obj) {
        if ((i & 2) != 0) {
            map = null;
        }
        return forUri(str, (Map<String, ? extends Object>) map);
    }

    @JvmStatic
    public static final ImageSource forUri(String uriString, Map<String, ? extends Object> extras) {
        return forUri(uriString != null ? uriParser.invoke(uriString) : null, extras);
    }

    @JvmStatic
    public static final ImageSource firstAvailable(ImageSource... imageSources) {
        Intrinsics.checkNotNullParameter(imageSources, "imageSources");
        return new FirstAvailableImageSource(imageSources);
    }

    @JvmStatic
    public static final ImageSource increasingQuality(ImageSource lowResImageSource, ImageSource highResImageSource) {
        Intrinsics.checkNotNullParameter(lowResImageSource, "lowResImageSource");
        Intrinsics.checkNotNullParameter(highResImageSource, "highResImageSource");
        return new IncreasingQualityImageSource(lowResImageSource, highResImageSource, null);
    }

    public static /* synthetic */ ImageSource increasingQuality$default(ImageSource imageSource, ImageSource imageSource2, Map map, int i, Object obj) {
        if ((i & 4) != 0) {
            map = null;
        }
        return increasingQuality(imageSource, imageSource2, map);
    }

    @JvmStatic
    public static final ImageSource increasingQuality(ImageSource lowResImageSource, ImageSource highResImageSource, Map<String, ? extends Object> extras) {
        Intrinsics.checkNotNullParameter(lowResImageSource, "lowResImageSource");
        Intrinsics.checkNotNullParameter(highResImageSource, "highResImageSource");
        return new IncreasingQualityImageSource(lowResImageSource, highResImageSource, extras);
    }

    @JvmStatic
    public static final ImageSource increasingQuality(Uri lowResImageUri, Uri highResImageUri) {
        if (lowResImageUri == null) {
            return forUri$default(highResImageUri, (Map) null, 2, (Object) null);
        }
        return new IncreasingQualityImageSource(forUri$default(lowResImageUri, (Map) null, 2, (Object) null), forUri$default(highResImageUri, (Map) null, 2, (Object) null), null, 4, null);
    }

    @JvmStatic
    public static final ImageSource bitmap(Bitmap bitmap) {
        Intrinsics.checkNotNullParameter(bitmap, "bitmap");
        return new BitmapImageSource(bitmap);
    }

    @JvmStatic
    public static final ImageSource drawable(Drawable drawable) {
        Intrinsics.checkNotNullParameter(drawable, "drawable");
        return new DrawableImageSource(drawable);
    }
}
