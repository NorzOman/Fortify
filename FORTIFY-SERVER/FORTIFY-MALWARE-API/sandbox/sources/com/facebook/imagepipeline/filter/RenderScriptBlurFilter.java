package com.facebook.imagepipeline.filter;

import android.content.Context;
import android.graphics.Bitmap;
import android.renderscript.Allocation;
import android.renderscript.Element;
import android.renderscript.RenderScript;
import android.renderscript.ScriptIntrinsicBlur;
import com.facebook.common.internal.Preconditions;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: RenderScriptBlurFilter.kt */
@Metadata(d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J(\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u0005H\u0007J\b\u0010\u000e\u001a\u00020\u000fH\u0007R\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T¢\u0006\u0002\n\u0000¨\u0006\u0010"}, d2 = {"Lcom/facebook/imagepipeline/filter/RenderScriptBlurFilter;", "", "<init>", "()V", "BLUR_MAX_RADIUS", "", "blurBitmap", "", "dest", "Landroid/graphics/Bitmap;", "src", "context", "Landroid/content/Context;", "radius", "canUseRenderScript", "", "imagepipeline_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class RenderScriptBlurFilter {
    public static final int BLUR_MAX_RADIUS = 25;
    public static final RenderScriptBlurFilter INSTANCE = new RenderScriptBlurFilter();

    @JvmStatic
    public static final boolean canUseRenderScript() {
        return true;
    }

    private RenderScriptBlurFilter() {
    }

    @JvmStatic
    public static final void blurBitmap(Bitmap dest, Bitmap src, Context context, int radius) throws Throwable {
        Intrinsics.checkNotNullParameter(dest, "dest");
        Intrinsics.checkNotNullParameter(src, "src");
        Intrinsics.checkNotNullParameter(context, "context");
        Preconditions.checkArgument(Boolean.valueOf(radius > 0 && radius <= 25));
        RenderScript renderScript = null;
        try {
            RenderScript renderScriptCreate = RenderScript.create(context);
            if (renderScriptCreate == null) {
                throw new IllegalStateException("Required value was null.".toString());
            }
            try {
                ScriptIntrinsicBlur scriptIntrinsicBlurCreate = ScriptIntrinsicBlur.create(renderScriptCreate, Element.U8_4(renderScriptCreate));
                Allocation allocationCreateFromBitmap = Allocation.createFromBitmap(renderScriptCreate, src);
                if (allocationCreateFromBitmap == null) {
                    throw new IllegalStateException("Required value was null.".toString());
                }
                Allocation allocationCreateFromBitmap2 = Allocation.createFromBitmap(renderScriptCreate, dest);
                if (allocationCreateFromBitmap2 == null) {
                    throw new IllegalStateException("Required value was null.".toString());
                }
                scriptIntrinsicBlurCreate.setRadius(radius);
                scriptIntrinsicBlurCreate.setInput(allocationCreateFromBitmap);
                scriptIntrinsicBlurCreate.forEach(allocationCreateFromBitmap2);
                allocationCreateFromBitmap2.copyTo(dest);
                scriptIntrinsicBlurCreate.destroy();
                allocationCreateFromBitmap.destroy();
                allocationCreateFromBitmap2.destroy();
                if (renderScriptCreate != null) {
                    renderScriptCreate.destroy();
                }
            } catch (Throwable th) {
                th = th;
                renderScript = renderScriptCreate;
                if (renderScript != null) {
                    renderScript.destroy();
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }
}
