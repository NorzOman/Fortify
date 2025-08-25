package com.facebook.fresco.ui.common;

import com.facebook.fresco.ui.common.ControllerListener2;
import com.facebook.react.uimanager.ViewProps;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ImagePerfState.kt */
@Metadata(d1 = {"\u0000l\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\b\u0007\n\u0002\u0010\t\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0003\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0014\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u00105\u001a\u000206J\u0006\u00107\u001a\u000206J\u0010\u00108\u001a\u0002062\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007J\u0010\u00109\u001a\u0002062\b\u0010\b\u001a\u0004\u0018\u00010\u0007J\u0010\u0010:\u001a\u0002062\b\u0010\t\u001a\u0004\u0018\u00010\nJ\u000e\u0010;\u001a\u0002062\u0006\u0010\u0011\u001a\u00020\u0012J\u000e\u0010<\u001a\u0002062\u0006\u0010\u0013\u001a\u00020\u0012J\u000e\u0010=\u001a\u0002062\u0006\u0010\u0014\u001a\u00020\u0012J\u000e\u0010>\u001a\u0002062\u0006\u0010\u0015\u001a\u00020\u0012J\u000e\u0010?\u001a\u0002062\u0006\u0010\u0016\u001a\u00020\u0012J\u000e\u0010@\u001a\u0002062\u0006\u0010\u0017\u001a\u00020\u0012J\u000e\u0010A\u001a\u0002062\u0006\u0010,\u001a\u00020\u0012J\u000e\u0010B\u001a\u0002062\u0006\u0010C\u001a\u00020\u0019J\u0010\u0010D\u001a\u0002062\b\u0010\u0010\u001a\u0004\u0018\u00010\nJ\u000e\u0010E\u001a\u0002062\u0006\u0010\u001a\u001a\u00020\u001bJ\u000e\u0010F\u001a\u0002062\u0006\u0010\u001c\u001a\u00020\u001bJ\u0010\u0010G\u001a\u0002062\b\u0010\u001d\u001a\u0004\u0018\u00010\u001eJ\u000e\u0010H\u001a\u0002062\u0006\u0010I\u001a\u00020\u0019J\u0006\u0010J\u001a\u00020KJ\u0010\u0010L\u001a\u0002062\b\u0010M\u001a\u0004\u0018\u000104R\u0010\u0010\u0006\u001a\u0004\u0018\u00010\u0007X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\b\u001a\u0004\u0018\u00010\u0007X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\t\u001a\u0004\u0018\u00010\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u001c\u0010\u000b\u001a\u0004\u0018\u00010\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR\u0010\u0010\u0010\u001a\u0004\u0018\u00010\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0011\u001a\u00020\u0012X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0013\u001a\u00020\u0012X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0014\u001a\u00020\u0012X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0015\u001a\u00020\u0012X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0016\u001a\u00020\u0012X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0017\u001a\u00020\u0012X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0018\u001a\u00020\u0019X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u001a\u001a\u00020\u001bX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u001c\u001a\u00020\u001bX\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\u001d\u001a\u0004\u0018\u00010\u001eX\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010\u001f\u001a\u00020 X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b!\u0010\"\"\u0004\b#\u0010$R\u000e\u0010%\u001a\u00020&X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010'\u001a\u00020\u0012X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b(\u0010)\"\u0004\b*\u0010+R\u000e\u0010,\u001a\u00020\u0012X\u0082\u000e¢\u0006\u0002\n\u0000R\u001c\u0010-\u001a\u0004\u0018\u00010.X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b/\u00100\"\u0004\b1\u00102R\u0010\u00103\u001a\u0004\u0018\u000104X\u0082\u000e¢\u0006\u0002\n\u0000R\u0013\u0010M\u001a\u0004\u0018\u00010\n8F¢\u0006\u0006\u001a\u0004\bN\u0010\r¨\u0006O"}, d2 = {"Lcom/facebook/fresco/ui/common/ImagePerfState;", "Lcom/facebook/fresco/ui/common/ImagePerfLoggingState;", "infra", "Lcom/facebook/fresco/ui/common/ImageRenderingInfra;", "<init>", "(Lcom/facebook/fresco/ui/common/ImageRenderingInfra;)V", "controllerId", "", "requestId", "imageRequest", "", "callerContext", "getCallerContext", "()Ljava/lang/Object;", "setCallerContext", "(Ljava/lang/Object;)V", "imageInfo", "controllerSubmitTimeMs", "", "controllerIntermediateImageSetTimeMs", "controllerFinalImageSetTimeMs", "controllerFailureTimeMs", "imageRequestStartTimeMs", "imageRequestEndTimeMs", "isPrefetch", "", "onScreenWidthPx", "", "onScreenHeightPx", "errorThrowable", "", "imageLoadStatus", "Lcom/facebook/fresco/ui/common/ImageLoadStatus;", "getImageLoadStatus", "()Lcom/facebook/fresco/ui/common/ImageLoadStatus;", "setImageLoadStatus", "(Lcom/facebook/fresco/ui/common/ImageLoadStatus;)V", "visibilityState", "Lcom/facebook/fresco/ui/common/VisibilityState;", "visibilityEventTimeMs", "getVisibilityEventTimeMs", "()J", "setVisibilityEventTimeMs", "(J)V", "invisibilityEventTimeMs", "dimensionsInfo", "Lcom/facebook/fresco/ui/common/DimensionsInfo;", "getDimensionsInfo", "()Lcom/facebook/fresco/ui/common/DimensionsInfo;", "setDimensionsInfo", "(Lcom/facebook/fresco/ui/common/DimensionsInfo;)V", "_extraData", "Lcom/facebook/fresco/ui/common/ControllerListener2$Extras;", "reset", "", "resetPointsTimestamps", "setControllerId", "setRequestId", "setImageRequest", "setControllerSubmitTimeMs", "setControllerIntermediateImageSetTimeMs", "setControllerFinalImageSetTimeMs", "setControllerFailureTimeMs", "setImageRequestStartTimeMs", "setImageRequestEndTimeMs", "setInvisibilityEventTimeMs", "setPrefetch", "prefetch", "setImageInfo", "setOnScreenWidth", "setOnScreenHeight", "setErrorThrowable", "setVisible", ViewProps.VISIBLE, "snapshot", "Lcom/facebook/fresco/ui/common/ImagePerfData;", "setExtraData", "extraData", "getExtraData", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ImagePerfState extends ImagePerfLoggingState {
    private ControllerListener2.Extras _extraData;
    private Object callerContext;
    private long controllerFailureTimeMs;
    private long controllerFinalImageSetTimeMs;
    private String controllerId;
    private long controllerIntermediateImageSetTimeMs;
    private long controllerSubmitTimeMs;
    private DimensionsInfo dimensionsInfo;
    private Throwable errorThrowable;
    private Object imageInfo;
    private ImageLoadStatus imageLoadStatus;
    private Object imageRequest;
    private long imageRequestEndTimeMs;
    private long imageRequestStartTimeMs;
    private long invisibilityEventTimeMs;
    private boolean isPrefetch;
    private int onScreenHeightPx;
    private int onScreenWidthPx;
    private String requestId;
    private long visibilityEventTimeMs;
    private VisibilityState visibilityState;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ImagePerfState(ImageRenderingInfra infra) {
        super(infra);
        Intrinsics.checkNotNullParameter(infra, "infra");
        this.controllerSubmitTimeMs = -1L;
        this.controllerIntermediateImageSetTimeMs = -1L;
        this.controllerFinalImageSetTimeMs = -1L;
        this.controllerFailureTimeMs = -1L;
        this.imageRequestStartTimeMs = -1L;
        this.imageRequestEndTimeMs = -1L;
        this.onScreenWidthPx = -1;
        this.onScreenHeightPx = -1;
        this.imageLoadStatus = ImageLoadStatus.UNKNOWN;
        this.visibilityState = VisibilityState.UNKNOWN;
        this.visibilityEventTimeMs = -1L;
        this.invisibilityEventTimeMs = -1L;
    }

    public final Object getCallerContext() {
        return this.callerContext;
    }

    public final void setCallerContext(Object obj) {
        this.callerContext = obj;
    }

    public final ImageLoadStatus getImageLoadStatus() {
        return this.imageLoadStatus;
    }

    public final void setImageLoadStatus(ImageLoadStatus imageLoadStatus) {
        Intrinsics.checkNotNullParameter(imageLoadStatus, "<set-?>");
        this.imageLoadStatus = imageLoadStatus;
    }

    public final long getVisibilityEventTimeMs() {
        return this.visibilityEventTimeMs;
    }

    public final void setVisibilityEventTimeMs(long j) {
        this.visibilityEventTimeMs = j;
    }

    public final DimensionsInfo getDimensionsInfo() {
        return this.dimensionsInfo;
    }

    public final void setDimensionsInfo(DimensionsInfo dimensionsInfo) {
        this.dimensionsInfo = dimensionsInfo;
    }

    public final void reset() {
        this.requestId = null;
        this.imageRequest = null;
        this.callerContext = null;
        this.imageInfo = null;
        this.isPrefetch = false;
        this.onScreenWidthPx = -1;
        this.onScreenHeightPx = -1;
        this.errorThrowable = null;
        this.imageLoadStatus = ImageLoadStatus.UNKNOWN;
        this.visibilityState = VisibilityState.UNKNOWN;
        this.dimensionsInfo = null;
        this._extraData = null;
        resetPointsTimestamps();
        resetLoggingState$ui_common_release();
    }

    public final void resetPointsTimestamps() {
        this.imageRequestStartTimeMs = -1L;
        this.imageRequestEndTimeMs = -1L;
        this.controllerSubmitTimeMs = -1L;
        this.controllerFinalImageSetTimeMs = -1L;
        this.controllerFailureTimeMs = -1L;
        this.visibilityEventTimeMs = -1L;
        this.invisibilityEventTimeMs = -1L;
        getIntermediateImageSetTimes().clear();
        setNewIntermediateImageSetPointAvailable(false);
        setEmptyEventTimestampNs(null);
        setReleasedEventTimestampNs(null);
    }

    public final void setControllerId(String controllerId) {
        this.controllerId = controllerId;
    }

    public final void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public final void setImageRequest(Object imageRequest) {
        this.imageRequest = imageRequest;
    }

    public final void setControllerSubmitTimeMs(long controllerSubmitTimeMs) {
        this.controllerSubmitTimeMs = controllerSubmitTimeMs;
    }

    public final void setControllerIntermediateImageSetTimeMs(long controllerIntermediateImageSetTimeMs) {
        this.controllerIntermediateImageSetTimeMs = controllerIntermediateImageSetTimeMs;
    }

    public final void setControllerFinalImageSetTimeMs(long controllerFinalImageSetTimeMs) {
        this.controllerFinalImageSetTimeMs = controllerFinalImageSetTimeMs;
    }

    public final void setControllerFailureTimeMs(long controllerFailureTimeMs) {
        this.controllerFailureTimeMs = controllerFailureTimeMs;
    }

    public final void setImageRequestStartTimeMs(long imageRequestStartTimeMs) {
        this.imageRequestStartTimeMs = imageRequestStartTimeMs;
    }

    public final void setImageRequestEndTimeMs(long imageRequestEndTimeMs) {
        this.imageRequestEndTimeMs = imageRequestEndTimeMs;
    }

    public final void setInvisibilityEventTimeMs(long invisibilityEventTimeMs) {
        this.invisibilityEventTimeMs = invisibilityEventTimeMs;
    }

    public final void setPrefetch(boolean prefetch) {
        this.isPrefetch = prefetch;
    }

    public final void setImageInfo(Object imageInfo) {
        this.imageInfo = imageInfo;
    }

    public final void setOnScreenWidth(int onScreenWidthPx) {
        this.onScreenWidthPx = onScreenWidthPx;
    }

    public final void setOnScreenHeight(int onScreenHeightPx) {
        this.onScreenHeightPx = onScreenHeightPx;
    }

    public final void setErrorThrowable(Throwable errorThrowable) {
        this.errorThrowable = errorThrowable;
    }

    public final void setVisible(boolean visible) {
        this.visibilityState = visible ? VisibilityState.VISIBLE : VisibilityState.INVISIBLE;
    }

    public final ImagePerfData snapshot() {
        return new ImagePerfData(getInfra(), this.controllerId, this.requestId, this.imageRequest, this.callerContext, this.imageInfo, this.controllerSubmitTimeMs, this.controllerIntermediateImageSetTimeMs, this.controllerFinalImageSetTimeMs, this.controllerFailureTimeMs, this.imageRequestStartTimeMs, this.imageRequestEndTimeMs, getEmptyEventTimestampNs(), getReleasedEventTimestampNs(), this.isPrefetch, this.onScreenWidthPx, this.onScreenHeightPx, this.errorThrowable, this.visibilityState, this.visibilityEventTimeMs, this.invisibilityEventTimeMs, this.dimensionsInfo, this._extraData, getCallingClassNameOnVisible(), getRootContextNameOnVisible(), getContextChainArrayOnVisible(), getContextChainExtrasOnVisible(), getContentIdOnVisible(), getSurfaceOnVisible(), getSubSurfaceOnVisible(), getMsSinceLastNavigationOnVisible(), getStartupStatusOnVisible(), CollectionsKt.toList(getIntermediateImageSetTimes()), getNewIntermediateImageSetPointAvailable(), getErrorMessageOnFailure(), getErrorStacktraceStringOnFailure(), getErrorCodeOnFailure(), getDensityDpiOnSuccess());
    }

    public final void setExtraData(ControllerListener2.Extras extraData) {
        this._extraData = extraData;
    }

    public final Object getExtraData() {
        return this._extraData;
    }
}
