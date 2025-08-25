package com.facebook.drawee.backends.pipeline.info.internal;

import com.facebook.common.time.MonotonicClock;
import com.facebook.drawee.drawable.VisibilityCallback;
import com.facebook.fresco.ui.common.BaseControllerListener2;
import com.facebook.fresco.ui.common.ControllerListener2;
import com.facebook.fresco.ui.common.DimensionsInfo;
import com.facebook.fresco.ui.common.ImageLoadStatus;
import com.facebook.fresco.ui.common.ImagePerfNotifier;
import com.facebook.fresco.ui.common.ImagePerfNotifierHolder;
import com.facebook.fresco.ui.common.ImagePerfState;
import com.facebook.fresco.ui.common.OnDrawControllerListener;
import com.facebook.fresco.ui.common.VisibilityAware;
import com.facebook.fresco.ui.common.VisibilityState;
import com.facebook.imagepipeline.image.ImageInfo;
import java.io.Closeable;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class ImagePerfStateManager extends BaseControllerListener2<ImageInfo> implements ImagePerfNotifierHolder, OnDrawControllerListener<ImageInfo>, Closeable, VisibilityAware, VisibilityCallback {
    private final MonotonicClock mClock;
    private final ImagePerfNotifier mImagePerfNotifier;
    private final ImagePerfState mImagePerfState;

    @Nullable
    private ImagePerfNotifier mLocalImagePerfNotifier;
    private final boolean mReportVisibleOnSubmitAndRelease;

    @Override // com.facebook.drawee.drawable.VisibilityCallback
    public void onDraw() {
    }

    public ImagePerfStateManager(MonotonicClock monotonicClock, ImagePerfState imagePerfState, ImagePerfNotifier imagePerfNotifier) {
        this(monotonicClock, imagePerfState, imagePerfNotifier, true);
    }

    public ImagePerfStateManager(MonotonicClock monotonicClock, ImagePerfState imagePerfState, ImagePerfNotifier imagePerfNotifier, boolean z) {
        this.mLocalImagePerfNotifier = null;
        this.mClock = monotonicClock;
        this.mImagePerfState = imagePerfState;
        this.mImagePerfNotifier = imagePerfNotifier;
        this.mReportVisibleOnSubmitAndRelease = z;
    }

    @Override // com.facebook.fresco.ui.common.ImagePerfNotifierHolder
    public void setImagePerfNotifier(@Nullable ImagePerfNotifier imagePerfNotifier) {
        this.mLocalImagePerfNotifier = imagePerfNotifier;
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onSubmit(String str, @Nullable Object obj, @Nullable ControllerListener2.Extras extras) {
        long jNow = this.mClock.now();
        ImagePerfState imagePerfState = this.mImagePerfState;
        imagePerfState.resetPointsTimestamps();
        imagePerfState.setControllerSubmitTimeMs(jNow);
        imagePerfState.setControllerId(str);
        imagePerfState.setCallerContext(obj);
        imagePerfState.setExtraData(extras);
        updateStatus(imagePerfState, ImageLoadStatus.REQUESTED);
        if (this.mReportVisibleOnSubmitAndRelease) {
            reportViewVisible(imagePerfState, jNow);
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onIntermediateImageSet(String str, @Nullable ImageInfo imageInfo) {
        long jNow = this.mClock.now();
        ImagePerfState imagePerfState = this.mImagePerfState;
        imagePerfState.setControllerIntermediateImageSetTimeMs(jNow);
        imagePerfState.setControllerId(str);
        imagePerfState.setImageInfo(imageInfo);
        updateStatus(imagePerfState, ImageLoadStatus.INTERMEDIATE_AVAILABLE);
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onFinalImageSet(String str, @Nullable ImageInfo imageInfo, @Nullable ControllerListener2.Extras extras) {
        long jNow = this.mClock.now();
        ImagePerfState imagePerfState = this.mImagePerfState;
        imagePerfState.setExtraData(extras);
        imagePerfState.setControllerFinalImageSetTimeMs(jNow);
        imagePerfState.setImageRequestEndTimeMs(jNow);
        imagePerfState.setControllerId(str);
        imagePerfState.setImageInfo(imageInfo);
        updateStatus(imagePerfState, ImageLoadStatus.SUCCESS);
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onFailure(String str, @Nullable Throwable th, @Nullable ControllerListener2.Extras extras) {
        long jNow = this.mClock.now();
        ImagePerfState imagePerfState = this.mImagePerfState;
        imagePerfState.setExtraData(extras);
        imagePerfState.setControllerFailureTimeMs(jNow);
        imagePerfState.setControllerId(str);
        imagePerfState.setErrorThrowable(th);
        updateStatus(imagePerfState, ImageLoadStatus.ERROR);
        reportViewInvisible(imagePerfState, jNow);
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onRelease(String str, @Nullable ControllerListener2.Extras extras) {
        long jNow = this.mClock.now();
        ImagePerfState imagePerfState = this.mImagePerfState;
        imagePerfState.setExtraData(extras);
        imagePerfState.setControllerId(str);
        updateStatus(imagePerfState, ImageLoadStatus.RELEASED);
        if (this.mReportVisibleOnSubmitAndRelease) {
            reportViewInvisible(imagePerfState, jNow);
        }
    }

    @Override // com.facebook.fresco.ui.common.OnDrawControllerListener
    public void onImageDrawn(String str, ImageInfo imageInfo, DimensionsInfo dimensionsInfo) {
        ImagePerfState imagePerfState = this.mImagePerfState;
        imagePerfState.setControllerId(str);
        imagePerfState.setDimensionsInfo(dimensionsInfo);
    }

    public void reportViewVisible(ImagePerfState imagePerfState, long j) {
        imagePerfState.setVisible(true);
        imagePerfState.setVisibilityEventTimeMs(j);
        updateVisibility(imagePerfState, VisibilityState.VISIBLE);
    }

    public void resetState() {
        this.mImagePerfState.reset();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        resetState();
    }

    private void reportViewInvisible(ImagePerfState imagePerfState, long j) {
        imagePerfState.setVisible(false);
        imagePerfState.setInvisibilityEventTimeMs(j);
        updateVisibility(imagePerfState, VisibilityState.INVISIBLE);
    }

    private void updateStatus(ImagePerfState imagePerfState, ImageLoadStatus imageLoadStatus) {
        imagePerfState.setImageLoadStatus(imageLoadStatus);
        this.mImagePerfNotifier.notifyStatusUpdated(imagePerfState, imageLoadStatus);
        ImagePerfNotifier imagePerfNotifier = this.mLocalImagePerfNotifier;
        if (imagePerfNotifier != null) {
            imagePerfNotifier.notifyStatusUpdated(imagePerfState, imageLoadStatus);
        }
    }

    private void updateVisibility(ImagePerfState imagePerfState, VisibilityState visibilityState) {
        this.mImagePerfNotifier.notifyVisibilityUpdated(imagePerfState, visibilityState);
        ImagePerfNotifier imagePerfNotifier = this.mLocalImagePerfNotifier;
        if (imagePerfNotifier != null) {
            imagePerfNotifier.notifyVisibilityUpdated(imagePerfState, visibilityState);
        }
    }

    @Override // com.facebook.fresco.ui.common.BaseControllerListener2, com.facebook.fresco.ui.common.ControllerListener2
    public void onEmptyEvent(@Nullable Object obj) {
        ImagePerfState imagePerfState = this.mImagePerfState;
        imagePerfState.setImageLoadStatus(ImageLoadStatus.EMPTY_EVENT);
        this.mImagePerfNotifier.notifyStatusUpdated(imagePerfState, ImageLoadStatus.EMPTY_EVENT);
        ImagePerfNotifier imagePerfNotifier = this.mLocalImagePerfNotifier;
        if (imagePerfNotifier != null) {
            imagePerfNotifier.notifyStatusUpdated(imagePerfState, ImageLoadStatus.EMPTY_EVENT);
        }
    }

    @Override // com.facebook.fresco.ui.common.VisibilityAware
    public void reportVisible(boolean z) {
        onVisibilityChange(z);
    }

    @Override // com.facebook.drawee.drawable.VisibilityCallback
    public void onVisibilityChange(boolean z) {
        if (z) {
            reportViewVisible(this.mImagePerfState, this.mClock.now());
        } else {
            reportViewInvisible(this.mImagePerfState, this.mClock.now());
        }
    }
}
