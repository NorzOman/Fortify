package com.facebook.drawee.drawable;

import android.graphics.ColorFilter;
import android.graphics.drawable.Drawable;
import kotlin.Metadata;

/* compiled from: DrawableProperties.kt */
@Metadata(d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\u0018\u0000 \u00142\u00020\u0001:\u0001\u0014B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u000e\u0010\f\u001a\u00020\r2\u0006\u0010\u0004\u001a\u00020\u0005J\u0010\u0010\u000e\u001a\u00020\r2\b\u0010\b\u001a\u0004\u0018\u00010\tJ\u000e\u0010\u000f\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u0007J\u000e\u0010\u0010\u001a\u00020\r2\u0006\u0010\u000b\u001a\u00020\u0007J\u0012\u0010\u0011\u001a\u00020\r2\b\u0010\u0012\u001a\u0004\u0018\u00010\u0013H\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\b\u001a\u0004\u0018\u00010\tX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0005X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\u0005X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u0015"}, d2 = {"Lcom/facebook/drawee/drawable/DrawableProperties;", "", "<init>", "()V", "alpha", "", "isSetColorFilter", "", "colorFilter", "Landroid/graphics/ColorFilter;", "dither", "filterBitmap", "setAlpha", "", "setColorFilter", "setDither", "setFilterBitmap", "applyTo", "drawable", "Landroid/graphics/drawable/Drawable;", "Companion", "drawee_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class DrawableProperties {
    private static final int UNSET = -1;
    private ColorFilter colorFilter;
    private boolean isSetColorFilter;
    private int alpha = -1;
    private int dither = -1;
    private int filterBitmap = -1;

    public final void setAlpha(int alpha) {
        this.alpha = alpha;
    }

    public final void setColorFilter(ColorFilter colorFilter) {
        this.colorFilter = colorFilter;
        this.isSetColorFilter = colorFilter != null;
    }

    public final void setDither(boolean dither) {
        this.dither = dither ? 1 : 0;
    }

    public final void setFilterBitmap(boolean filterBitmap) {
        this.filterBitmap = filterBitmap ? 1 : 0;
    }

    public final void applyTo(Drawable drawable) {
        if (drawable == null) {
            return;
        }
        int i = this.alpha;
        if (i != -1) {
            drawable.setAlpha(i);
        }
        if (this.isSetColorFilter) {
            drawable.setColorFilter(this.colorFilter);
        }
        int i2 = this.dither;
        if (i2 != -1) {
            drawable.setDither(i2 != 0);
        }
        int i3 = this.filterBitmap;
        if (i3 != -1) {
            drawable.setFilterBitmap(i3 != 0);
        }
    }
}
