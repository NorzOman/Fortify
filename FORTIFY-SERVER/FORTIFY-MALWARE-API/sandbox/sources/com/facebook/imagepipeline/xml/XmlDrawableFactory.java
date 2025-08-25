package com.facebook.imagepipeline.xml;

import android.graphics.drawable.Drawable;
import com.facebook.imagepipeline.drawable.DrawableFactory;
import com.facebook.imagepipeline.image.CloseableImage;
import com.facebook.imagepipeline.image.CloseableXml;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: XmlDrawableFactory.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0000\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0016J\u0012\u0010\b\u001a\u0004\u0018\u00010\t2\u0006\u0010\u0006\u001a\u00020\u0007H\u0016¨\u0006\n"}, d2 = {"Lcom/facebook/imagepipeline/xml/XmlDrawableFactory;", "Lcom/facebook/imagepipeline/drawable/DrawableFactory;", "<init>", "()V", "supportsImageType", "", "image", "Lcom/facebook/imagepipeline/image/CloseableImage;", "createDrawable", "Landroid/graphics/drawable/Drawable;", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class XmlDrawableFactory implements DrawableFactory {
    @Override // com.facebook.imagepipeline.drawable.DrawableFactory
    public boolean supportsImageType(CloseableImage image) {
        Intrinsics.checkNotNullParameter(image, "image");
        return image instanceof CloseableXml;
    }

    @Override // com.facebook.imagepipeline.drawable.DrawableFactory
    public Drawable createDrawable(CloseableImage image) {
        Intrinsics.checkNotNullParameter(image, "image");
        CloseableXml closeableXml = image instanceof CloseableXml ? (CloseableXml) image : null;
        if (closeableXml != null) {
            return closeableXml.buildDrawable();
        }
        return null;
    }
}
