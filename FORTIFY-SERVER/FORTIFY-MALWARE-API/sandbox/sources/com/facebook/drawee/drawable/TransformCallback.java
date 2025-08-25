package com.facebook.drawee.drawable;

import android.graphics.Matrix;
import android.graphics.RectF;
import com.facebook.react.uimanager.ViewProps;
import kotlin.Metadata;

/* compiled from: TransformCallback.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\bH&¨\u0006\t"}, d2 = {"Lcom/facebook/drawee/drawable/TransformCallback;", "", "getTransform", "", ViewProps.TRANSFORM, "Landroid/graphics/Matrix;", "getRootBounds", "bounds", "Landroid/graphics/RectF;", "drawee_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface TransformCallback {
    void getRootBounds(RectF bounds);

    void getTransform(Matrix transform);
}
