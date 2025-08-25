package com.facebook.react.devsupport;

import android.app.Activity;
import android.util.Pair;
import android.view.View;
import com.facebook.react.bridge.DefaultJSExceptionHandler;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.common.SurfaceDelegate;
import com.facebook.react.devsupport.interfaces.BundleLoadCallback;
import com.facebook.react.devsupport.interfaces.DevOptionHandler;
import com.facebook.react.devsupport.interfaces.DevSplitBundleCallback;
import com.facebook.react.devsupport.interfaces.DevSupportManager;
import com.facebook.react.devsupport.interfaces.ErrorCustomizer;
import com.facebook.react.devsupport.interfaces.ErrorType;
import com.facebook.react.devsupport.interfaces.PackagerStatusCallback;
import com.facebook.react.devsupport.interfaces.RedBoxHandler;
import com.facebook.react.devsupport.interfaces.StackFrame;
import com.facebook.react.modules.debug.interfaces.DeveloperSettings;
import java.io.File;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ReleaseDevSupportManager.kt */
@Metadata(d1 = {"\u0000È\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0003\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u000b\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0016\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u001c\u0010\u0006\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\t2\b\u0010\n\u001a\u0004\u0018\u00010\u000bH\u0016J\u001c\u0010\f\u001a\u00020\u00072\b\u0010\r\u001a\u0004\u0018\u00010\t2\b\u0010\u000e\u001a\u0004\u0018\u00010\u000fH\u0016J$\u0010\u0010\u001a\u00020\u00072\b\u0010\b\u001a\u0004\u0018\u00010\t2\b\u0010\u0011\u001a\u0004\u0018\u00010\u00122\u0006\u0010\u0013\u001a\u00020\u0014H\u0016J\u0014\u0010\u0015\u001a\u0004\u0018\u00010\u00162\b\u0010\u0017\u001a\u0004\u0018\u00010\tH\u0016J\u0012\u0010\u0018\u001a\u00020\u00072\b\u0010\u0019\u001a\u0004\u0018\u00010\u0016H\u0016J\b\u0010\u001a\u001a\u00020\u0007H\u0016J\b\u0010\u001b\u001a\u00020\u0007H\u0016J\b\u0010\u001c\u001a\u00020\u0007H\u0016J\b\u0010\u001d\u001a\u00020\u0007H\u0016J\u0010\u0010\u001e\u001a\u00020\u00072\u0006\u0010\u001f\u001a\u00020 H\u0016J\u0010\u0010!\u001a\u00020\u00072\u0006\u0010\"\u001a\u00020 H\u0016J\u0010\u0010#\u001a\u00020\u00072\u0006\u0010$\u001a\u00020 H\u0016J\b\u0010%\u001a\u00020\u0007H\u0016J\u0010\u00104\u001a\u00020\u00072\u0006\u00105\u001a\u000206H\u0016J\u0010\u00107\u001a\u00020\u00072\u0006\u00105\u001a\u000206H\u0016J\b\u0010A\u001a\u00020 H\u0016J\b\u0010B\u001a\u00020\u0007H\u0016J\b\u0010C\u001a\u00020\u0007H\u0016J\u0018\u0010D\u001a\u00020\u00072\u0006\u0010E\u001a\u00020\t2\u0006\u0010F\u001a\u00020GH\u0016J\u0018\u0010H\u001a\u00020\u00072\u0006\u0010I\u001a\u00020\t2\u0006\u0010F\u001a\u00020JH\u0016J\u0010\u0010K\u001a\u00020\u00072\u0006\u0010F\u001a\u00020LH\u0016J\u001c\u0010M\u001a\u0004\u0018\u00010N2\u0006\u0010O\u001a\u00020\t2\b\u0010P\u001a\u0004\u0018\u00010NH\u0016J\u0012\u0010_\u001a\u00020\u00072\b\u0010`\u001a\u0004\u0018\u00010aH\u0016J8\u0010b\u001a\u0016\u0012\u0004\u0012\u00020\t\u0012\n\u0012\b\u0012\u0004\u0012\u00020U0T\u0018\u00010c2\u001a\u0010d\u001a\u0016\u0012\u0004\u0012\u00020\t\u0012\n\u0012\b\u0012\u0004\u0012\u00020U0T\u0018\u00010cH\u0016J\u0012\u0010e\u001a\u00020\u00072\b\u0010f\u001a\u0004\u0018\u00010gH\u0016J\u0014\u0010h\u001a\u00020\u00072\n\u0010\n\u001a\u00060ij\u0002`jH\u0016J\u0014\u0010r\u001a\u0004\u0018\u00010s2\b\u0010t\u001a\u0004\u0018\u00010\tH\u0016J\b\u0010u\u001a\u00020\u0007H\u0016J\u0018\u0010v\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\u0006\u0010w\u001a\u00020xH\u0016J\b\u0010y\u001a\u00020\u0007H\u0016J\u0018\u0010z\u001a\u00020\u00072\u0006\u0010{\u001a\u00020\t2\u0006\u0010|\u001a\u00020\tH\u0016R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R$\u0010'\u001a\u00020 2\u0006\u0010&\u001a\u00020 8V@VX\u0096\u000e¢\u0006\f\u001a\u0004\b(\u0010)\"\u0004\b*\u0010+R\u0016\u0010,\u001a\u0004\u0018\u00010-8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b.\u0010/R\u0016\u00100\u001a\u0004\u0018\u0001018VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b2\u00103R\u0016\u00108\u001a\u0004\u0018\u00010\t8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b9\u0010:R\u0016\u0010;\u001a\u0004\u0018\u00010\t8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b<\u0010:R\u0016\u0010=\u001a\u0004\u0018\u00010\t8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b>\u0010:R\u0016\u0010?\u001a\u0004\u0018\u00010\t8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b@\u0010:R\u0016\u0010Q\u001a\u0004\u0018\u00010\t8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\bR\u0010:R\u001c\u0010S\u001a\n\u0012\u0004\u0012\u00020U\u0018\u00010T8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\bV\u0010WR\u0016\u0010X\u001a\u0004\u0018\u00010Y8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\bZ\u0010[R\u0014\u0010\\\u001a\u00020\u0014X\u0096D¢\u0006\b\n\u0000\u001a\u0004\b]\u0010^R\u0016\u0010k\u001a\u0004\u0018\u00010l8VX\u0096\u0004¢\u0006\u0006\u001a\u0004\bm\u0010nR\u0016\u0010o\u001a\u0004\u0018\u0001068VX\u0096\u0004¢\u0006\u0006\u001a\u0004\bp\u0010q¨\u0006}"}, d2 = {"Lcom/facebook/react/devsupport/ReleaseDevSupportManager;", "Lcom/facebook/react/devsupport/interfaces/DevSupportManager;", "<init>", "()V", "defaultJSExceptionHandler", "Lcom/facebook/react/bridge/DefaultJSExceptionHandler;", "showNewJavaError", "", StackTraceHelper.MESSAGE_KEY, "", "e", "", "addCustomDevOption", "optionName", "optionHandler", "Lcom/facebook/react/devsupport/interfaces/DevOptionHandler;", "showNewJSError", "details", "Lcom/facebook/react/bridge/ReadableArray;", "errorCookie", "", "createRootView", "Landroid/view/View;", "appKey", "destroyRootView", "rootView", "hideRedboxDialog", "showDevOptionsDialog", "startInspector", "stopInspector", "setHotModuleReplacementEnabled", "isHotModuleReplacementEnabled", "", "setRemoteJSDebugEnabled", "isRemoteJSDebugEnabled", "setFpsDebugEnabled", "isFpsDebugEnabled", "toggleElementInspector", "isDevSupportEnabled", "devSupportEnabled", "getDevSupportEnabled", "()Z", "setDevSupportEnabled", "(Z)V", "devSettings", "Lcom/facebook/react/modules/debug/interfaces/DeveloperSettings;", "getDevSettings", "()Lcom/facebook/react/modules/debug/interfaces/DeveloperSettings;", "redBoxHandler", "Lcom/facebook/react/devsupport/interfaces/RedBoxHandler;", "getRedBoxHandler", "()Lcom/facebook/react/devsupport/interfaces/RedBoxHandler;", "onNewReactContextCreated", "reactContext", "Lcom/facebook/react/bridge/ReactContext;", "onReactInstanceDestroyed", "sourceMapUrl", "getSourceMapUrl", "()Ljava/lang/String;", "sourceUrl", "getSourceUrl", "jSBundleURLForRemoteDebugging", "getJSBundleURLForRemoteDebugging", "downloadedJSBundleFile", "getDownloadedJSBundleFile", "hasUpToDateJSBundleInCache", "reloadSettings", "handleReloadJS", "reloadJSFromServer", "bundleURL", "callback", "Lcom/facebook/react/devsupport/interfaces/BundleLoadCallback;", "loadSplitBundleFromServer", "bundlePath", "Lcom/facebook/react/devsupport/interfaces/DevSplitBundleCallback;", "isPackagerRunning", "Lcom/facebook/react/devsupport/interfaces/PackagerStatusCallback;", "downloadBundleResourceFromUrlSync", "Ljava/io/File;", "resourceURL", "outputFile", "lastErrorTitle", "getLastErrorTitle", "lastErrorStack", "", "Lcom/facebook/react/devsupport/interfaces/StackFrame;", "getLastErrorStack", "()[Lcom/facebook/react/devsupport/interfaces/StackFrame;", "lastErrorType", "Lcom/facebook/react/devsupport/interfaces/ErrorType;", "getLastErrorType", "()Lcom/facebook/react/devsupport/interfaces/ErrorType;", "lastErrorCookie", "getLastErrorCookie", "()I", "registerErrorCustomizer", "errorCustomizer", "Lcom/facebook/react/devsupport/interfaces/ErrorCustomizer;", "processErrorCustomizers", "Landroid/util/Pair;", "errorInfo", "setPackagerLocationCustomizer", "packagerLocationCustomizer", "Lcom/facebook/react/devsupport/interfaces/DevSupportManager$PackagerLocationCustomizer;", "handleException", "Ljava/lang/Exception;", "Lkotlin/Exception;", "currentActivity", "Landroid/app/Activity;", "getCurrentActivity", "()Landroid/app/Activity;", "currentReactContext", "getCurrentReactContext", "()Lcom/facebook/react/bridge/ReactContext;", "createSurfaceDelegate", "Lcom/facebook/react/common/SurfaceDelegate;", "moduleName", "openDebugger", "showPausedInDebuggerOverlay", "listener", "Lcom/facebook/react/devsupport/interfaces/DevSupportManager$PausedInDebuggerOverlayCommandListener;", "hidePausedInDebuggerOverlay", "setAdditionalOptionForPackager", "name", "value", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class ReleaseDevSupportManager implements DevSupportManager {
    private final DefaultJSExceptionHandler defaultJSExceptionHandler = new DefaultJSExceptionHandler();
    private final int lastErrorCookie;

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void addCustomDevOption(String optionName, DevOptionHandler optionHandler) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public View createRootView(String appKey) {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public SurfaceDelegate createSurfaceDelegate(String moduleName) {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void destroyRootView(View rootView) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public File downloadBundleResourceFromUrlSync(String resourceURL, File outputFile) {
        Intrinsics.checkNotNullParameter(resourceURL, "resourceURL");
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public Activity getCurrentActivity() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public ReactContext getCurrentReactContext() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public DeveloperSettings getDevSettings() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public boolean getDevSupportEnabled() {
        return false;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public String getDownloadedJSBundleFile() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public String getJSBundleURLForRemoteDebugging() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public StackFrame[] getLastErrorStack() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public String getLastErrorTitle() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public ErrorType getLastErrorType() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public RedBoxHandler getRedBoxHandler() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public String getSourceMapUrl() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public String getSourceUrl() {
        return null;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void handleReloadJS() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public boolean hasUpToDateJSBundleInCache() {
        return false;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void hidePausedInDebuggerOverlay() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void hideRedboxDialog() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void loadSplitBundleFromServer(String bundlePath, DevSplitBundleCallback callback) {
        Intrinsics.checkNotNullParameter(bundlePath, "bundlePath");
        Intrinsics.checkNotNullParameter(callback, "callback");
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void onNewReactContextCreated(ReactContext reactContext) {
        Intrinsics.checkNotNullParameter(reactContext, "reactContext");
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void onReactInstanceDestroyed(ReactContext reactContext) {
        Intrinsics.checkNotNullParameter(reactContext, "reactContext");
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void openDebugger() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public Pair<String, StackFrame[]> processErrorCustomizers(Pair<String, StackFrame[]> errorInfo) {
        return errorInfo;
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void registerErrorCustomizer(ErrorCustomizer errorCustomizer) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void reloadJSFromServer(String bundleURL, BundleLoadCallback callback) {
        Intrinsics.checkNotNullParameter(bundleURL, "bundleURL");
        Intrinsics.checkNotNullParameter(callback, "callback");
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void reloadSettings() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void setAdditionalOptionForPackager(String name, String value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void setDevSupportEnabled(boolean z) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void setFpsDebugEnabled(boolean isFpsDebugEnabled) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void setHotModuleReplacementEnabled(boolean isHotModuleReplacementEnabled) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void setPackagerLocationCustomizer(DevSupportManager.PackagerLocationCustomizer packagerLocationCustomizer) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void setRemoteJSDebugEnabled(boolean isRemoteJSDebugEnabled) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void showDevOptionsDialog() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void showNewJSError(String message, ReadableArray details, int errorCookie) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void showNewJavaError(String message, Throwable e) {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void showPausedInDebuggerOverlay(String message, DevSupportManager.PausedInDebuggerOverlayCommandListener listener) {
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(listener, "listener");
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void startInspector() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void stopInspector() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void toggleElementInspector() {
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public void isPackagerRunning(PackagerStatusCallback callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        callback.onPackagerStatusFetched(false);
    }

    @Override // com.facebook.react.devsupport.interfaces.DevSupportManager
    public int getLastErrorCookie() {
        return this.lastErrorCookie;
    }

    @Override // com.facebook.react.bridge.JSExceptionHandler
    public void handleException(Exception e) {
        Intrinsics.checkNotNullParameter(e, "e");
        this.defaultJSExceptionHandler.handleException(e);
    }
}
