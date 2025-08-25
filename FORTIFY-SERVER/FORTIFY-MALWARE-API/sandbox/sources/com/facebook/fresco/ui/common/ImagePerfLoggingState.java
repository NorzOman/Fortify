package com.facebook.fresco.ui.common;

import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ImagePerfLoggingState.kt */
@Metadata(d1 = {"\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0016\n\u0002\u0010\u0011\n\u0002\b\u001e\n\u0002\u0010\b\n\u0002\b\t\n\u0002\u0010\u0002\n\u0002\b\u0002\b\u0016\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\r\u0010O\u001a\u00020PH\u0000¢\u0006\u0002\bQR\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007R#\u0010\b\u001a\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00020\u000b\u0012\u0004\u0012\u00020\f0\n0\t¢\u0006\b\n\u0000\u001a\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u00020\u0010X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R\u001e\u0010\u0015\u001a\u0004\u0018\u00010\fX\u0086\u000e¢\u0006\u0010\n\u0002\u0010\u001a\u001a\u0004\b\u0016\u0010\u0017\"\u0004\b\u0018\u0010\u0019R\u001e\u0010\u001b\u001a\u0004\u0018\u00010\fX\u0086\u000e¢\u0006\u0010\n\u0002\u0010\u001a\u001a\u0004\b\u001c\u0010\u0017\"\u0004\b\u001d\u0010\u0019R\u001c\u0010\u001e\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001f\u0010 \"\u0004\b!\u0010\"R\u001c\u0010#\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b$\u0010 \"\u0004\b%\u0010\"R$\u0010&\u001a\n\u0012\u0004\u0012\u00020\u000b\u0018\u00010'X\u0086\u000e¢\u0006\u0010\n\u0002\u0010,\u001a\u0004\b(\u0010)\"\u0004\b*\u0010+R\u001c\u0010-\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b.\u0010 \"\u0004\b/\u0010\"R\u001c\u00100\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b1\u0010 \"\u0004\b2\u0010\"R\u001c\u00103\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b4\u0010 \"\u0004\b5\u0010\"R\u001c\u00106\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b7\u0010 \"\u0004\b8\u0010\"R\u001e\u00109\u001a\u0004\u0018\u00010\fX\u0086\u000e¢\u0006\u0010\n\u0002\u0010\u001a\u001a\u0004\b:\u0010\u0017\"\u0004\b;\u0010\u0019R\u001c\u0010<\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b=\u0010 \"\u0004\b>\u0010\"R\u001c\u0010?\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b@\u0010 \"\u0004\bA\u0010\"R\u001c\u0010B\u001a\u0004\u0018\u00010\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bC\u0010 \"\u0004\bD\u0010\"R\u001e\u0010E\u001a\u0004\u0018\u00010FX\u0086\u000e¢\u0006\u0010\n\u0002\u0010K\u001a\u0004\bG\u0010H\"\u0004\bI\u0010JR\u001e\u0010L\u001a\u0004\u0018\u00010FX\u0086\u000e¢\u0006\u0010\n\u0002\u0010K\u001a\u0004\bM\u0010H\"\u0004\bN\u0010J¨\u0006R"}, d2 = {"Lcom/facebook/fresco/ui/common/ImagePerfLoggingState;", "", "infra", "Lcom/facebook/fresco/ui/common/ImageRenderingInfra;", "<init>", "(Lcom/facebook/fresco/ui/common/ImageRenderingInfra;)V", "getInfra", "()Lcom/facebook/fresco/ui/common/ImageRenderingInfra;", "intermediateImageSetTimes", "", "Lkotlin/Pair;", "", "", "getIntermediateImageSetTimes", "()Ljava/util/List;", "newIntermediateImageSetPointAvailable", "", "getNewIntermediateImageSetPointAvailable", "()Z", "setNewIntermediateImageSetPointAvailable", "(Z)V", "emptyEventTimestampNs", "getEmptyEventTimestampNs", "()Ljava/lang/Long;", "setEmptyEventTimestampNs", "(Ljava/lang/Long;)V", "Ljava/lang/Long;", "releasedEventTimestampNs", "getReleasedEventTimestampNs", "setReleasedEventTimestampNs", "callingClassNameOnVisible", "getCallingClassNameOnVisible", "()Ljava/lang/String;", "setCallingClassNameOnVisible", "(Ljava/lang/String;)V", "rootContextNameOnVisible", "getRootContextNameOnVisible", "setRootContextNameOnVisible", "contextChainArrayOnVisible", "", "getContextChainArrayOnVisible", "()[Ljava/lang/String;", "setContextChainArrayOnVisible", "([Ljava/lang/String;)V", "[Ljava/lang/String;", "contextChainExtrasOnVisible", "getContextChainExtrasOnVisible", "setContextChainExtrasOnVisible", "contentIdOnVisible", "getContentIdOnVisible", "setContentIdOnVisible", "surfaceOnVisible", "getSurfaceOnVisible", "setSurfaceOnVisible", "subSurfaceOnVisible", "getSubSurfaceOnVisible", "setSubSurfaceOnVisible", "msSinceLastNavigationOnVisible", "getMsSinceLastNavigationOnVisible", "setMsSinceLastNavigationOnVisible", "startupStatusOnVisible", "getStartupStatusOnVisible", "setStartupStatusOnVisible", "errorMessageOnFailure", "getErrorMessageOnFailure", "setErrorMessageOnFailure", "errorStacktraceStringOnFailure", "getErrorStacktraceStringOnFailure", "setErrorStacktraceStringOnFailure", "errorCodeOnFailure", "", "getErrorCodeOnFailure", "()Ljava/lang/Integer;", "setErrorCodeOnFailure", "(Ljava/lang/Integer;)V", "Ljava/lang/Integer;", "densityDpiOnSuccess", "getDensityDpiOnSuccess", "setDensityDpiOnSuccess", "resetLoggingState", "", "resetLoggingState$ui_common_release", "ui-common_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class ImagePerfLoggingState {
    private String callingClassNameOnVisible;
    private String contentIdOnVisible;
    private String[] contextChainArrayOnVisible;
    private String contextChainExtrasOnVisible;
    private Integer densityDpiOnSuccess;
    private Long emptyEventTimestampNs;
    private Integer errorCodeOnFailure;
    private String errorMessageOnFailure;
    private String errorStacktraceStringOnFailure;
    private final ImageRenderingInfra infra;
    private final List<Pair<String, Long>> intermediateImageSetTimes;
    private Long msSinceLastNavigationOnVisible;
    private boolean newIntermediateImageSetPointAvailable;
    private Long releasedEventTimestampNs;
    private String rootContextNameOnVisible;
    private String startupStatusOnVisible;
    private String subSurfaceOnVisible;
    private String surfaceOnVisible;

    public ImagePerfLoggingState(ImageRenderingInfra infra) {
        Intrinsics.checkNotNullParameter(infra, "infra");
        this.infra = infra;
        this.intermediateImageSetTimes = new ArrayList();
    }

    public final ImageRenderingInfra getInfra() {
        return this.infra;
    }

    public final List<Pair<String, Long>> getIntermediateImageSetTimes() {
        return this.intermediateImageSetTimes;
    }

    public final boolean getNewIntermediateImageSetPointAvailable() {
        return this.newIntermediateImageSetPointAvailable;
    }

    public final void setNewIntermediateImageSetPointAvailable(boolean z) {
        this.newIntermediateImageSetPointAvailable = z;
    }

    public final Long getEmptyEventTimestampNs() {
        return this.emptyEventTimestampNs;
    }

    public final void setEmptyEventTimestampNs(Long l) {
        this.emptyEventTimestampNs = l;
    }

    public final Long getReleasedEventTimestampNs() {
        return this.releasedEventTimestampNs;
    }

    public final void setReleasedEventTimestampNs(Long l) {
        this.releasedEventTimestampNs = l;
    }

    public final String getCallingClassNameOnVisible() {
        return this.callingClassNameOnVisible;
    }

    public final void setCallingClassNameOnVisible(String str) {
        this.callingClassNameOnVisible = str;
    }

    public final String getRootContextNameOnVisible() {
        return this.rootContextNameOnVisible;
    }

    public final void setRootContextNameOnVisible(String str) {
        this.rootContextNameOnVisible = str;
    }

    public final String[] getContextChainArrayOnVisible() {
        return this.contextChainArrayOnVisible;
    }

    public final void setContextChainArrayOnVisible(String[] strArr) {
        this.contextChainArrayOnVisible = strArr;
    }

    public final String getContextChainExtrasOnVisible() {
        return this.contextChainExtrasOnVisible;
    }

    public final void setContextChainExtrasOnVisible(String str) {
        this.contextChainExtrasOnVisible = str;
    }

    public final String getContentIdOnVisible() {
        return this.contentIdOnVisible;
    }

    public final void setContentIdOnVisible(String str) {
        this.contentIdOnVisible = str;
    }

    public final String getSurfaceOnVisible() {
        return this.surfaceOnVisible;
    }

    public final void setSurfaceOnVisible(String str) {
        this.surfaceOnVisible = str;
    }

    public final String getSubSurfaceOnVisible() {
        return this.subSurfaceOnVisible;
    }

    public final void setSubSurfaceOnVisible(String str) {
        this.subSurfaceOnVisible = str;
    }

    public final Long getMsSinceLastNavigationOnVisible() {
        return this.msSinceLastNavigationOnVisible;
    }

    public final void setMsSinceLastNavigationOnVisible(Long l) {
        this.msSinceLastNavigationOnVisible = l;
    }

    public final String getStartupStatusOnVisible() {
        return this.startupStatusOnVisible;
    }

    public final void setStartupStatusOnVisible(String str) {
        this.startupStatusOnVisible = str;
    }

    public final String getErrorMessageOnFailure() {
        return this.errorMessageOnFailure;
    }

    public final void setErrorMessageOnFailure(String str) {
        this.errorMessageOnFailure = str;
    }

    public final String getErrorStacktraceStringOnFailure() {
        return this.errorStacktraceStringOnFailure;
    }

    public final void setErrorStacktraceStringOnFailure(String str) {
        this.errorStacktraceStringOnFailure = str;
    }

    public final Integer getErrorCodeOnFailure() {
        return this.errorCodeOnFailure;
    }

    public final void setErrorCodeOnFailure(Integer num) {
        this.errorCodeOnFailure = num;
    }

    public final Integer getDensityDpiOnSuccess() {
        return this.densityDpiOnSuccess;
    }

    public final void setDensityDpiOnSuccess(Integer num) {
        this.densityDpiOnSuccess = num;
    }

    public final void resetLoggingState$ui_common_release() {
        this.intermediateImageSetTimes.clear();
        this.newIntermediateImageSetPointAvailable = false;
        this.emptyEventTimestampNs = null;
        this.releasedEventTimestampNs = null;
        this.callingClassNameOnVisible = null;
        this.rootContextNameOnVisible = null;
        this.contextChainArrayOnVisible = null;
        this.contextChainExtrasOnVisible = null;
        this.contentIdOnVisible = null;
        this.surfaceOnVisible = null;
        this.subSurfaceOnVisible = null;
        this.msSinceLastNavigationOnVisible = null;
        this.startupStatusOnVisible = null;
        this.errorMessageOnFailure = null;
        this.errorStacktraceStringOnFailure = null;
        this.errorCodeOnFailure = null;
        this.densityDpiOnSuccess = null;
    }
}
