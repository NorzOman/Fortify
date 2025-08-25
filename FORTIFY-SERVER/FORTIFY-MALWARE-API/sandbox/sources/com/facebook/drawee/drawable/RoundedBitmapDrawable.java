package com.facebook.drawee.drawable;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import com.facebook.imagepipeline.systrace.FrescoSystrace;
import java.lang.ref.WeakReference;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class RoundedBitmapDrawable extends RoundedDrawable {
    private static boolean sDefaultRepeatEdgePixels = false;

    @Nullable
    private final Bitmap mBitmap;

    @Nullable
    private RectF mBitmapClipRect;
    private final Paint mBorderPaint;

    @Nullable
    private WeakReference<Bitmap> mLastBitmap;
    private final Paint mPaint;
    private boolean mRepeatEdgePixels;

    public static void setDefaultRepeatEdgePixels(boolean z) {
        sDefaultRepeatEdgePixels = z;
    }

    public static boolean getDefaultRepeatEdgePixels() {
        return sDefaultRepeatEdgePixels;
    }

    public RoundedBitmapDrawable(Resources resources, @Nullable Bitmap bitmap, @Nullable Paint paint, boolean z) {
        super(new BitmapDrawable(resources, bitmap));
        Paint paint2 = new Paint();
        this.mPaint = paint2;
        Paint paint3 = new Paint(1);
        this.mBorderPaint = paint3;
        this.mBitmapClipRect = null;
        this.mBitmap = bitmap;
        if (paint != null) {
            paint2.set(paint);
        }
        paint2.setFlags(1);
        paint3.setStyle(Paint.Style.STROKE);
        this.mRepeatEdgePixels = z;
    }

    public RoundedBitmapDrawable(Resources resources, @Nullable Bitmap bitmap, @Nullable Paint paint) {
        this(resources, bitmap, paint, sDefaultRepeatEdgePixels);
    }

    public RoundedBitmapDrawable(Resources resources, @Nullable Bitmap bitmap) {
        this(resources, bitmap, null);
    }

    @Override // com.facebook.drawee.drawable.RoundedDrawable
    protected void updateTransform() {
        super.updateTransform();
        if (this.mRepeatEdgePixels) {
            return;
        }
        if (this.mBitmapClipRect == null) {
            this.mBitmapClipRect = new RectF();
        }
        this.mTransform.mapRect(this.mBitmapClipRect, this.mBitmapBounds);
    }

    @Override // com.facebook.drawee.drawable.RoundedDrawable, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        if (FrescoSystrace.isTracing()) {
            FrescoSystrace.beginSection("RoundedBitmapDrawable#draw");
        }
        if (!shouldRound()) {
            super.draw(canvas);
            if (FrescoSystrace.isTracing()) {
                FrescoSystrace.endSection();
                return;
            }
            return;
        }
        updateTransform();
        updatePath();
        updatePaint();
        int iSave = canvas.save();
        canvas.concat(this.mInverseParentTransform);
        if (!this.mRepeatEdgePixels && this.mBitmapClipRect != null) {
            int iSave2 = canvas.save();
            canvas.clipRect(this.mBitmapClipRect);
            canvas.drawPath(this.mPath, this.mPaint);
            canvas.restoreToCount(iSave2);
        } else {
            canvas.drawPath(this.mPath, this.mPaint);
        }
        if (this.mBorderWidth > 0.0f) {
            this.mBorderPaint.setStrokeWidth(this.mBorderWidth);
            this.mBorderPaint.setColor(DrawableUtils.multiplyColorAlpha(this.mBorderColor, this.mPaint.getAlpha()));
            canvas.drawPath(this.mBorderPath, this.mBorderPaint);
        }
        canvas.restoreToCount(iSave);
        if (FrescoSystrace.isTracing()) {
            FrescoSystrace.endSection();
        }
    }

    private void updatePaint() {
        Shader shader;
        WeakReference<Bitmap> weakReference = this.mLastBitmap;
        if (weakReference == null || weakReference.get() != this.mBitmap) {
            this.mLastBitmap = new WeakReference<>(this.mBitmap);
            if (this.mBitmap != null) {
                this.mPaint.setShader(new BitmapShader(this.mBitmap, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP));
                this.mIsShaderTransformDirty = true;
            }
        }
        if (this.mIsShaderTransformDirty && (shader = this.mPaint.getShader()) != null) {
            shader.setLocalMatrix(this.mTransform);
            this.mIsShaderTransformDirty = false;
        }
        this.mPaint.setFilterBitmap(getPaintFilterBitmap());
    }

    public static RoundedBitmapDrawable fromBitmapDrawable(Resources resources, BitmapDrawable bitmapDrawable) {
        return new RoundedBitmapDrawable(resources, bitmapDrawable.getBitmap(), bitmapDrawable.getPaint());
    }

    @Override // com.facebook.drawee.drawable.RoundedDrawable
    boolean shouldRound() {
        return super.shouldRound() && this.mBitmap != null;
    }

    @Override // com.facebook.drawee.drawable.RoundedDrawable, android.graphics.drawable.Drawable
    public void setAlpha(int i) {
        super.setAlpha(i);
        if (i != this.mPaint.getAlpha()) {
            this.mPaint.setAlpha(i);
            super.setAlpha(i);
            invalidateSelf();
        }
    }

    @Override // com.facebook.drawee.drawable.RoundedDrawable, android.graphics.drawable.Drawable
    public void setColorFilter(@Nullable ColorFilter colorFilter) {
        super.setColorFilter(colorFilter);
        this.mPaint.setColorFilter(colorFilter);
    }

    public Paint getPaint() {
        return this.mPaint;
    }

    @Override // com.facebook.drawee.drawable.RoundedDrawable, com.facebook.drawee.drawable.Rounded
    public void setRepeatEdgePixels(boolean z) {
        this.mRepeatEdgePixels = z;
    }

    @Nullable
    public Bitmap getBitmap() {
        return this.mBitmap;
    }

    public boolean getRepeatEdgePixels() {
        return this.mRepeatEdgePixels;
    }
}
