package com.facebook.react.uimanager.drawable;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathEffect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import com.facebook.react.uimanager.PixelUtil;
import com.facebook.react.uimanager.ViewProps;
import com.facebook.react.uimanager.style.BorderRadiusStyle;
import com.facebook.react.uimanager.style.ComputedBorderRadius;
import com.facebook.react.uimanager.style.CornerRadii;
import com.facebook.react.uimanager.style.OutlineStyle;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;

/* compiled from: OutlineDrawable.kt */
@Metadata(d1 = {"\u0000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0000\u0018\u00002\u00020\u0001B;\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\n\b\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\b\u001a\u00020\t\u0012\u0006\u0010\n\u001a\u00020\u000b\u0012\u0006\u0010\f\u001a\u00020\t¢\u0006\u0004\b\r\u0010\u000eJ\u0010\u0010+\u001a\u00020,2\u0006\u0010-\u001a\u00020\u0007H\u0016J\u0012\u0010.\u001a\u00020,2\b\u0010/\u001a\u0004\u0018\u000100H\u0016J\b\u00101\u001a\u00020\u0007H\u0017J\u0010\u00102\u001a\u00020,2\u0006\u00103\u001a\u000204H\u0016J\b\u00105\u001a\u00020,H\u0002J\u001a\u00106\u001a\u0004\u0018\u0001072\u0006\u00108\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\tH\u0002J\u0018\u00109\u001a\u00020\t2\u0006\u0010:\u001a\u00020\t2\u0006\u0010\f\u001a\u00020\tH\u0002J\u0010\u0010;\u001a\u00020,2\u0006\u00103\u001a\u000204H\u0002J\u0010\u0010<\u001a\u00020,2\u0006\u00103\u001a\u000204H\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u001c\u0010\u0004\u001a\u0004\u0018\u00010\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\u0012R\u000e\u0010\u0013\u001a\u00020\tX\u0082D¢\u0006\u0002\n\u0000R$\u0010\b\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\t@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0015\u0010\u0016\"\u0004\b\u0017\u0010\u0018R$\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0014\u001a\u00020\u000b@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0019\u0010\u001a\"\u0004\b\u001b\u0010\u001cR$\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0014\u001a\u00020\u0007@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001d\u0010\u001e\"\u0004\b\u001f\u0010 R$\u0010\f\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\t@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b!\u0010\u0016\"\u0004\b\"\u0010\u0018R\u000e\u0010#\u001a\u00020$X\u0082\u0004¢\u0006\u0002\n\u0000R\u0010\u0010%\u001a\u0004\u0018\u00010&X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010'\u001a\u00020(X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010)\u001a\u00020*X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006="}, d2 = {"Lcom/facebook/react/uimanager/drawable/OutlineDrawable;", "Landroid/graphics/drawable/Drawable;", "context", "Landroid/content/Context;", ViewProps.BORDER_RADIUS, "Lcom/facebook/react/uimanager/style/BorderRadiusStyle;", ViewProps.OUTLINE_COLOR, "", ViewProps.OUTLINE_OFFSET, "", ViewProps.OUTLINE_STYLE, "Lcom/facebook/react/uimanager/style/OutlineStyle;", ViewProps.OUTLINE_WIDTH, "<init>", "(Landroid/content/Context;Lcom/facebook/react/uimanager/style/BorderRadiusStyle;IFLcom/facebook/react/uimanager/style/OutlineStyle;F)V", "getBorderRadius", "()Lcom/facebook/react/uimanager/style/BorderRadiusStyle;", "setBorderRadius", "(Lcom/facebook/react/uimanager/style/BorderRadiusStyle;)V", "gapBetweenPaths", "value", "getOutlineOffset", "()F", "setOutlineOffset", "(F)V", "getOutlineStyle", "()Lcom/facebook/react/uimanager/style/OutlineStyle;", "setOutlineStyle", "(Lcom/facebook/react/uimanager/style/OutlineStyle;)V", "getOutlineColor", "()I", "setOutlineColor", "(I)V", "getOutlineWidth", "setOutlineWidth", "outlinePaint", "Landroid/graphics/Paint;", "computedBorderRadius", "Lcom/facebook/react/uimanager/style/ComputedBorderRadius;", "tempRectForOutline", "Landroid/graphics/RectF;", "pathForOutline", "Landroid/graphics/Path;", "setAlpha", "", "alpha", "setColorFilter", "colorFilter", "Landroid/graphics/ColorFilter;", "getOpacity", "draw", "canvas", "Landroid/graphics/Canvas;", "updateOutlineRect", "getPathEffect", "Landroid/graphics/PathEffect;", "style", "calculateRadius", "radius", "drawRectangularOutline", "drawRoundedOutline", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class OutlineDrawable extends Drawable {
    private BorderRadiusStyle borderRadius;
    private ComputedBorderRadius computedBorderRadius;
    private final Context context;
    private final float gapBetweenPaths;
    private int outlineColor;
    private float outlineOffset;
    private final Paint outlinePaint;
    private OutlineStyle outlineStyle;
    private float outlineWidth;
    private final Path pathForOutline;
    private RectF tempRectForOutline;

    /* compiled from: OutlineDrawable.kt */
    @Metadata(k = 3, mv = {2, 0, 0}, xi = 48)
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[OutlineStyle.values().length];
            try {
                iArr[OutlineStyle.SOLID.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[OutlineStyle.DASHED.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[OutlineStyle.DOTTED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    private final float calculateRadius(float radius, float outlineWidth) {
        if (radius == 0.0f) {
            return 0.0f;
        }
        return radius + (outlineWidth * 0.5f);
    }

    public /* synthetic */ OutlineDrawable(Context context, BorderRadiusStyle borderRadiusStyle, int i, float f, OutlineStyle outlineStyle, float f2, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : borderRadiusStyle, i, f, outlineStyle, f2);
    }

    public final BorderRadiusStyle getBorderRadius() {
        return this.borderRadius;
    }

    public final void setBorderRadius(BorderRadiusStyle borderRadiusStyle) {
        this.borderRadius = borderRadiusStyle;
    }

    public OutlineDrawable(Context context, BorderRadiusStyle borderRadiusStyle, int i, float f, OutlineStyle outlineStyle, float f2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(outlineStyle, "outlineStyle");
        this.context = context;
        this.borderRadius = borderRadiusStyle;
        this.gapBetweenPaths = 0.8f;
        this.outlineOffset = f;
        this.outlineStyle = outlineStyle;
        this.outlineColor = i;
        this.outlineWidth = f2;
        Paint paint = new Paint();
        paint.setStyle(Paint.Style.STROKE);
        paint.setColor(i);
        paint.setStrokeWidth(f2);
        paint.setPathEffect(getPathEffect(outlineStyle, f2));
        this.outlinePaint = paint;
        this.tempRectForOutline = new RectF();
        this.pathForOutline = new Path();
    }

    public final float getOutlineOffset() {
        return this.outlineOffset;
    }

    public final void setOutlineOffset(float f) {
        if (f == this.outlineOffset) {
            return;
        }
        this.outlineOffset = f;
        invalidateSelf();
    }

    public final OutlineStyle getOutlineStyle() {
        return this.outlineStyle;
    }

    public final void setOutlineStyle(OutlineStyle value) {
        Intrinsics.checkNotNullParameter(value, "value");
        if (value != this.outlineStyle) {
            this.outlineStyle = value;
            this.outlinePaint.setPathEffect(getPathEffect(value, this.outlineWidth));
            invalidateSelf();
        }
    }

    public final int getOutlineColor() {
        return this.outlineColor;
    }

    public final void setOutlineColor(int i) {
        if (i != this.outlineColor) {
            this.outlineColor = i;
            this.outlinePaint.setColor(i);
            invalidateSelf();
        }
    }

    public final float getOutlineWidth() {
        return this.outlineWidth;
    }

    public final void setOutlineWidth(float f) {
        if (f == this.outlineWidth) {
            return;
        }
        this.outlineWidth = f;
        this.outlinePaint.setStrokeWidth(f);
        this.outlinePaint.setPathEffect(getPathEffect(this.outlineStyle, f));
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        this.outlinePaint.setAlpha(MathKt.roundToInt((alpha / 255.0f) * (Color.alpha(this.outlineColor) / 255.0f) * 255.0f));
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.outlinePaint.setColorFilter(colorFilter);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    @Deprecated(message = "Deprecated in Java")
    public int getOpacity() {
        int alpha = this.outlinePaint.getAlpha();
        if (alpha == 255) {
            return -1;
        }
        return (1 > alpha || alpha >= 255) ? -2 : -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        if (this.outlineWidth == 0.0f) {
            return;
        }
        this.pathForOutline.reset();
        BorderRadiusStyle borderRadiusStyle = this.borderRadius;
        this.computedBorderRadius = borderRadiusStyle != null ? borderRadiusStyle.resolve(getLayoutDirection(), this.context, PixelUtil.INSTANCE.pxToDp(getBounds().width()), PixelUtil.INSTANCE.pxToDp(getBounds().height())) : null;
        updateOutlineRect();
        ComputedBorderRadius computedBorderRadius = this.computedBorderRadius;
        if (computedBorderRadius != null && computedBorderRadius != null && computedBorderRadius.hasRoundedBorders()) {
            drawRoundedOutline(canvas);
        } else {
            drawRectangularOutline(canvas);
        }
    }

    private final void updateOutlineRect() {
        this.tempRectForOutline.set(getBounds());
        this.tempRectForOutline.top -= ((this.outlineWidth * 0.5f) + this.outlineOffset) - this.gapBetweenPaths;
        this.tempRectForOutline.bottom += ((this.outlineWidth * 0.5f) + this.outlineOffset) - this.gapBetweenPaths;
        this.tempRectForOutline.left -= ((this.outlineWidth * 0.5f) + this.outlineOffset) - this.gapBetweenPaths;
        this.tempRectForOutline.right += ((this.outlineWidth * 0.5f) + this.outlineOffset) - this.gapBetweenPaths;
    }

    private final PathEffect getPathEffect(OutlineStyle style, float outlineWidth) {
        int i = WhenMappings.$EnumSwitchMapping$0[style.ordinal()];
        if (i == 1) {
            return null;
        }
        if (i == 2) {
            float f = outlineWidth * 3;
            return new DashPathEffect(new float[]{f, f, f, f}, 0.0f);
        }
        if (i != 3) {
            throw new NoWhenBranchMatchedException();
        }
        return new DashPathEffect(new float[]{outlineWidth, outlineWidth, outlineWidth, outlineWidth}, 0.0f);
    }

    private final void drawRectangularOutline(Canvas canvas) {
        this.pathForOutline.addRect(this.tempRectForOutline, Path.Direction.CW);
        canvas.drawPath(this.pathForOutline, this.outlinePaint);
    }

    private final void drawRoundedOutline(Canvas canvas) {
        CornerRadii cornerRadii;
        CornerRadii cornerRadii2;
        CornerRadii cornerRadii3;
        CornerRadii cornerRadii4;
        CornerRadii bottomRight;
        CornerRadii bottomLeft;
        CornerRadii topRight;
        CornerRadii topLeft;
        ComputedBorderRadius computedBorderRadius = this.computedBorderRadius;
        if (computedBorderRadius == null || (topLeft = computedBorderRadius.getTopLeft()) == null || (cornerRadii = topLeft.toPixelFromDIP()) == null) {
            cornerRadii = new CornerRadii(0.0f, 0.0f);
        }
        ComputedBorderRadius computedBorderRadius2 = this.computedBorderRadius;
        if (computedBorderRadius2 == null || (topRight = computedBorderRadius2.getTopRight()) == null || (cornerRadii2 = topRight.toPixelFromDIP()) == null) {
            cornerRadii2 = new CornerRadii(0.0f, 0.0f);
        }
        ComputedBorderRadius computedBorderRadius3 = this.computedBorderRadius;
        if (computedBorderRadius3 == null || (bottomLeft = computedBorderRadius3.getBottomLeft()) == null || (cornerRadii3 = bottomLeft.toPixelFromDIP()) == null) {
            cornerRadii3 = new CornerRadii(0.0f, 0.0f);
        }
        ComputedBorderRadius computedBorderRadius4 = this.computedBorderRadius;
        if (computedBorderRadius4 == null || (bottomRight = computedBorderRadius4.getBottomRight()) == null || (cornerRadii4 = bottomRight.toPixelFromDIP()) == null) {
            cornerRadii4 = new CornerRadii(0.0f, 0.0f);
        }
        this.pathForOutline.addRoundRect(this.tempRectForOutline, new float[]{calculateRadius(cornerRadii.getHorizontal(), this.outlineWidth), calculateRadius(cornerRadii.getVertical(), this.outlineWidth), calculateRadius(cornerRadii2.getHorizontal(), this.outlineWidth), calculateRadius(cornerRadii2.getVertical(), this.outlineWidth), calculateRadius(cornerRadii4.getHorizontal(), this.outlineWidth), calculateRadius(cornerRadii4.getVertical(), this.outlineWidth), calculateRadius(cornerRadii3.getHorizontal(), this.outlineWidth), calculateRadius(cornerRadii3.getVertical(), this.outlineWidth)}, Path.Direction.CW);
        canvas.drawPath(this.pathForOutline, this.outlinePaint);
    }
}
