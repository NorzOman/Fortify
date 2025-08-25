package com.facebook.imagepipeline.transformation;

import android.graphics.Bitmap;
import com.facebook.common.references.CloseableReference;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: TransformationUtils.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\"\u0010\u0004\u001a\u00020\u00052\b\u0010\u0006\u001a\u0004\u0018\u00010\u00072\u000e\u0010\b\u001a\n\u0012\u0004\u0012\u00020\n\u0018\u00010\tH\u0007¨\u0006\u000b"}, d2 = {"Lcom/facebook/imagepipeline/transformation/TransformationUtils;", "", "<init>", "()V", "maybeApplyTransformation", "", "transformation", "Lcom/facebook/imagepipeline/transformation/BitmapTransformation;", "bitmapReference", "Lcom/facebook/common/references/CloseableReference;", "Landroid/graphics/Bitmap;", "imagepipeline-base_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TransformationUtils {
    public static final TransformationUtils INSTANCE = new TransformationUtils();

    private TransformationUtils() {
    }

    @JvmStatic
    public static final boolean maybeApplyTransformation(BitmapTransformation transformation, CloseableReference<Bitmap> bitmapReference) {
        if (transformation == null || bitmapReference == null) {
            return false;
        }
        Bitmap bitmap = bitmapReference.get();
        Intrinsics.checkNotNullExpressionValue(bitmap, "get(...)");
        Bitmap bitmap2 = bitmap;
        if (transformation.modifiesTransparency()) {
            bitmap2.setHasAlpha(true);
        }
        transformation.transform(bitmap2);
        return true;
    }
}
