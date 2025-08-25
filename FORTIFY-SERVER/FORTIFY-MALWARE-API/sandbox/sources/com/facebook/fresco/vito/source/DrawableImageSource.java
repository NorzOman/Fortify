package com.facebook.fresco.vito.source;

import android.graphics.drawable.Drawable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: DrawableImageSource.kt */
@Metadata(d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\b\u0086\b\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0013\u0010\b\u001a\u00020\t2\b\u0010\n\u001a\u0004\u0018\u00010\u000bH\u0096\u0002J\b\u0010\f\u001a\u00020\rH\u0016J\t\u0010\u000e\u001a\u00020\u0003HÆ\u0003J\u0013\u0010\u000f\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u0003HÆ\u0001J\t\u0010\u0010\u001a\u00020\u0011HÖ\u0001R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\u0012"}, d2 = {"Lcom/facebook/fresco/vito/source/DrawableImageSource;", "Lcom/facebook/fresco/vito/source/ImageSource;", "drawable", "Landroid/graphics/drawable/Drawable;", "<init>", "(Landroid/graphics/drawable/Drawable;)V", "getDrawable", "()Landroid/graphics/drawable/Drawable;", "equals", "", "other", "", "hashCode", "", "component1", "copy", "toString", "", "source_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final /* data */ class DrawableImageSource implements ImageSource {
    private final Drawable drawable;

    public static /* synthetic */ DrawableImageSource copy$default(DrawableImageSource drawableImageSource, Drawable drawable, int i, Object obj) {
        if ((i & 1) != 0) {
            drawable = drawableImageSource.drawable;
        }
        return drawableImageSource.copy(drawable);
    }

    /* renamed from: component1, reason: from getter */
    public final Drawable getDrawable() {
        return this.drawable;
    }

    public final DrawableImageSource copy(Drawable drawable) {
        Intrinsics.checkNotNullParameter(drawable, "drawable");
        return new DrawableImageSource(drawable);
    }

    public String toString() {
        return "DrawableImageSource(drawable=" + this.drawable + ")";
    }

    public DrawableImageSource(Drawable drawable) {
        Intrinsics.checkNotNullParameter(drawable, "drawable");
        this.drawable = drawable;
    }

    public final Drawable getDrawable() {
        return this.drawable;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!Intrinsics.areEqual(getClass(), other != null ? other.getClass() : null)) {
            return false;
        }
        Intrinsics.checkNotNull(other, "null cannot be cast to non-null type com.facebook.fresco.vito.source.DrawableImageSource");
        return Intrinsics.areEqual(this.drawable, ((DrawableImageSource) other).drawable);
    }

    public int hashCode() {
        return this.drawable.hashCode();
    }
}
