package com.facebook.react.views.image;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import com.facebook.drawee.controller.ControllerListener;
import com.facebook.drawee.drawable.ForwardingDrawable;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReactImageDownloadListener.kt */
@Metadata(d1 = {"\u0000F\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0003\n\u0002\b\u0005\b\u0010\u0018\u0000  *\u0004\b\u0000\u0010\u00012\u00020\u00022\b\u0012\u0004\u0012\u0002H\u00010\u0003:\u0002\u001f B\u0007¢\u0006\u0004\b\u0004\u0010\u0005J\u0018\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\tH\u0016J\u0010\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\tH\u0014J\u001a\u0010\u000e\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00102\b\u0010\u0011\u001a\u0004\u0018\u00010\u0012H\u0016J)\u0010\u0013\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00102\b\u0010\u0014\u001a\u0004\u0018\u00018\u00002\b\u0010\u0015\u001a\u0004\u0018\u00010\u0016H\u0016¢\u0006\u0002\u0010\u0017J\u001f\u0010\u0018\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00102\b\u0010\u0014\u001a\u0004\u0018\u00018\u0000H\u0016¢\u0006\u0002\u0010\u0019J\u0018\u0010\u001a\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u001b\u001a\u00020\u001cH\u0016J\u0018\u0010\u001d\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u001b\u001a\u00020\u001cH\u0016J\u0010\u0010\u001e\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u0010H\u0016¨\u0006!"}, d2 = {"Lcom/facebook/react/views/image/ReactImageDownloadListener;", "INFO", "Lcom/facebook/drawee/drawable/ForwardingDrawable;", "Lcom/facebook/drawee/controller/ControllerListener;", "<init>", "()V", "onProgressChange", "", "loaded", "", "total", "onLevelChange", "", "level", "onSubmit", "id", "", "callerContext", "", "onFinalImageSet", "imageInfo", "animatable", "Landroid/graphics/drawable/Animatable;", "(Ljava/lang/String;Ljava/lang/Object;Landroid/graphics/drawable/Animatable;)V", "onIntermediateImageSet", "(Ljava/lang/String;Ljava/lang/Object;)V", "onIntermediateImageFailed", "throwable", "", "onFailure", "onRelease", "EmptyDrawable", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class ReactImageDownloadListener<INFO> extends ForwardingDrawable implements ControllerListener<INFO> {
    private static final int MAX_LEVEL = 10000;

    /* compiled from: ReactImageDownloadListener.kt */
    @Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0002\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0016J\u0010\u0010\b\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\nH\u0016J\u0012\u0010\u000b\u001a\u00020\u00052\b\u0010\f\u001a\u0004\u0018\u00010\rH\u0016J\b\u0010\u000e\u001a\u00020\nH\u0017¨\u0006\u000f"}, d2 = {"Lcom/facebook/react/views/image/ReactImageDownloadListener$EmptyDrawable;", "Landroid/graphics/drawable/Drawable;", "<init>", "()V", "draw", "", "canvas", "Landroid/graphics/Canvas;", "setAlpha", "alpha", "", "setColorFilter", "colorFilter", "Landroid/graphics/ColorFilter;", "getOpacity", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class EmptyDrawable extends Drawable {
        @Override // android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            Intrinsics.checkNotNullParameter(canvas, "canvas");
        }

        @Override // android.graphics.drawable.Drawable
        @Deprecated(message = "Deprecated in Java")
        public int getOpacity() {
            return -1;
        }

        @Override // android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
        }

        @Override // android.graphics.drawable.Drawable
        public void setColorFilter(ColorFilter colorFilter) {
        }
    }

    @Override // com.facebook.drawee.controller.ControllerListener
    public void onFailure(String id, Throwable throwable) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(throwable, "throwable");
    }

    @Override // com.facebook.drawee.controller.ControllerListener
    public void onFinalImageSet(String id, INFO imageInfo, Animatable animatable) {
        Intrinsics.checkNotNullParameter(id, "id");
    }

    @Override // com.facebook.drawee.controller.ControllerListener
    public void onIntermediateImageFailed(String id, Throwable throwable) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(throwable, "throwable");
    }

    @Override // com.facebook.drawee.controller.ControllerListener
    public void onIntermediateImageSet(String id, INFO imageInfo) {
        Intrinsics.checkNotNullParameter(id, "id");
    }

    public void onProgressChange(int loaded, int total) {
    }

    @Override // com.facebook.drawee.controller.ControllerListener
    public void onRelease(String id) {
        Intrinsics.checkNotNullParameter(id, "id");
    }

    @Override // com.facebook.drawee.controller.ControllerListener
    public void onSubmit(String id, Object callerContext) {
        Intrinsics.checkNotNullParameter(id, "id");
    }

    public ReactImageDownloadListener() {
        super(new EmptyDrawable());
    }

    @Override // com.facebook.drawee.drawable.ForwardingDrawable, android.graphics.drawable.Drawable
    protected boolean onLevelChange(int level) {
        onProgressChange(level, MAX_LEVEL);
        return super.onLevelChange(level);
    }
}
