package com.facebook.react.devsupport.interfaces;

import android.app.Activity;
import android.util.Pair;
import android.view.View;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.common.SurfaceDelegate;
import com.facebook.react.devsupport.StackTraceHelper;
import com.facebook.react.modules.debug.interfaces.DeveloperSettings;
import java.io.File;
import kotlin.Metadata;

/* compiled from: DevSupportManager.kt */
@Metadata(d1 = {"\u0000¾\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u000b\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0003\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\bf\u0018\u00002\u00020\u0001:\u0002uvJ\u001c\u00101\u001a\u0002022\b\u00103\u001a\u0004\u0018\u00010\u000b2\b\u00104\u001a\u0004\u0018\u000105H&J\u001c\u00106\u001a\u0002022\b\u00107\u001a\u0004\u0018\u00010\u000b2\b\u00108\u001a\u0004\u0018\u000109H&J\u0014\u0010:\u001a\u0004\u0018\u00010;2\b\u0010<\u001a\u0004\u0018\u00010\u000bH&J\u0012\u0010=\u001a\u0002022\b\u0010>\u001a\u0004\u0018\u00010;H&J$\u0010?\u001a\u0002022\b\u00103\u001a\u0004\u0018\u00010\u000b2\b\u0010@\u001a\u0004\u0018\u00010A2\u0006\u0010B\u001a\u00020 H&J\b\u0010C\u001a\u000202H&J\b\u0010D\u001a\u000202H&J\b\u0010E\u001a\u000202H&J\b\u0010F\u001a\u000202H&J\u0010\u0010G\u001a\u0002022\u0006\u0010H\u001a\u00020(H&J\u0010\u0010I\u001a\u0002022\u0006\u0010H\u001a\u00020(H&J\b\u0010J\u001a\u00020,H&J\b\u0010K\u001a\u000202H&J\b\u0010L\u001a\u000202H&J\u0018\u0010M\u001a\u0002022\u0006\u0010N\u001a\u00020\u000b2\u0006\u0010O\u001a\u00020PH&J\u0018\u0010Q\u001a\u0002022\u0006\u0010R\u001a\u00020\u000b2\u0006\u0010O\u001a\u00020SH&J\u0010\u0010T\u001a\u0002022\u0006\u0010O\u001a\u00020UH&J\u0010\u0010V\u001a\u0002022\u0006\u0010W\u001a\u00020,H&J\u0010\u0010X\u001a\u0002022\u0006\u0010Y\u001a\u00020,H&J\u0010\u0010Z\u001a\u0002022\u0006\u0010[\u001a\u00020,H&J\b\u0010\\\u001a\u000202H&J\u001c\u0010]\u001a\u0004\u0018\u00010^2\u0006\u0010_\u001a\u00020\u000b2\b\u0010`\u001a\u0004\u0018\u00010^H&J\u0012\u0010a\u001a\u0002022\b\u0010b\u001a\u0004\u0018\u00010cH&J8\u0010d\u001a\u0016\u0012\u0004\u0012\u00020\u000b\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00180\u0017\u0018\u00010e2\u001a\u0010f\u001a\u0016\u0012\u0004\u0012\u00020\u000b\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00180\u0017\u0018\u00010eH&J\u0012\u0010g\u001a\u0002022\b\u0010h\u001a\u0004\u0018\u00010iH&J\u0014\u0010j\u001a\u0004\u0018\u00010k2\b\u0010l\u001a\u0004\u0018\u00010\u000bH&J\b\u0010m\u001a\u000202H&J\u0018\u0010n\u001a\u0002022\u0006\u00103\u001a\u00020\u000b2\u0006\u0010o\u001a\u00020pH&J\b\u0010q\u001a\u000202H&J\u0018\u0010r\u001a\u0002022\u0006\u0010s\u001a\u00020\u000b2\u0006\u0010t\u001a\u00020\u000bH&R\u0014\u0010\u0002\u001a\u0004\u0018\u00010\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005R\u0014\u0010\u0006\u001a\u0004\u0018\u00010\u0007X¦\u0004¢\u0006\u0006\u001a\u0004\b\b\u0010\tR\u0014\u0010\n\u001a\u0004\u0018\u00010\u000bX¦\u0004¢\u0006\u0006\u001a\u0004\b\f\u0010\rR\u0014\u0010\u000e\u001a\u0004\u0018\u00010\u000bX¦\u0004¢\u0006\u0006\u001a\u0004\b\u000f\u0010\rR\u0014\u0010\u0010\u001a\u0004\u0018\u00010\u000bX¦\u0004¢\u0006\u0006\u001a\u0004\b\u0011\u0010\rR\u0014\u0010\u0012\u001a\u0004\u0018\u00010\u000bX¦\u0004¢\u0006\u0006\u001a\u0004\b\u0013\u0010\rR\u0014\u0010\u0014\u001a\u0004\u0018\u00010\u000bX¦\u0004¢\u0006\u0006\u001a\u0004\b\u0015\u0010\rR\u001a\u0010\u0016\u001a\n\u0012\u0004\u0012\u00020\u0018\u0018\u00010\u0017X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001aR\u0014\u0010\u001b\u001a\u0004\u0018\u00010\u001cX¦\u0004¢\u0006\u0006\u001a\u0004\b\u001d\u0010\u001eR\u0012\u0010\u001f\u001a\u00020 X¦\u0004¢\u0006\u0006\u001a\u0004\b!\u0010\"R\u0014\u0010#\u001a\u0004\u0018\u00010$X¦\u0004¢\u0006\u0006\u001a\u0004\b%\u0010&R\u0014\u0010'\u001a\u0004\u0018\u00010(X¦\u0004¢\u0006\u0006\u001a\u0004\b)\u0010*R\u0018\u0010+\u001a\u00020,X¦\u000e¢\u0006\f\u001a\u0004\b-\u0010.\"\u0004\b/\u00100ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006wÀ\u0006\u0001"}, d2 = {"Lcom/facebook/react/devsupport/interfaces/DevSupportManager;", "Lcom/facebook/react/bridge/JSExceptionHandler;", "devSettings", "Lcom/facebook/react/modules/debug/interfaces/DeveloperSettings;", "getDevSettings", "()Lcom/facebook/react/modules/debug/interfaces/DeveloperSettings;", "redBoxHandler", "Lcom/facebook/react/devsupport/interfaces/RedBoxHandler;", "getRedBoxHandler", "()Lcom/facebook/react/devsupport/interfaces/RedBoxHandler;", "sourceMapUrl", "", "getSourceMapUrl", "()Ljava/lang/String;", "sourceUrl", "getSourceUrl", "jSBundleURLForRemoteDebugging", "getJSBundleURLForRemoteDebugging", "downloadedJSBundleFile", "getDownloadedJSBundleFile", "lastErrorTitle", "getLastErrorTitle", "lastErrorStack", "", "Lcom/facebook/react/devsupport/interfaces/StackFrame;", "getLastErrorStack", "()[Lcom/facebook/react/devsupport/interfaces/StackFrame;", "lastErrorType", "Lcom/facebook/react/devsupport/interfaces/ErrorType;", "getLastErrorType", "()Lcom/facebook/react/devsupport/interfaces/ErrorType;", "lastErrorCookie", "", "getLastErrorCookie", "()I", "currentActivity", "Landroid/app/Activity;", "getCurrentActivity", "()Landroid/app/Activity;", "currentReactContext", "Lcom/facebook/react/bridge/ReactContext;", "getCurrentReactContext", "()Lcom/facebook/react/bridge/ReactContext;", "devSupportEnabled", "", "getDevSupportEnabled", "()Z", "setDevSupportEnabled", "(Z)V", "showNewJavaError", "", StackTraceHelper.MESSAGE_KEY, "e", "", "addCustomDevOption", "optionName", "optionHandler", "Lcom/facebook/react/devsupport/interfaces/DevOptionHandler;", "createRootView", "Landroid/view/View;", "appKey", "destroyRootView", "rootView", "showNewJSError", "details", "Lcom/facebook/react/bridge/ReadableArray;", "errorCookie", "hideRedboxDialog", "showDevOptionsDialog", "startInspector", "stopInspector", "onNewReactContextCreated", "reactContext", "onReactInstanceDestroyed", "hasUpToDateJSBundleInCache", "reloadSettings", "handleReloadJS", "reloadJSFromServer", "bundleURL", "callback", "Lcom/facebook/react/devsupport/interfaces/BundleLoadCallback;", "loadSplitBundleFromServer", "bundlePath", "Lcom/facebook/react/devsupport/interfaces/DevSplitBundleCallback;", "isPackagerRunning", "Lcom/facebook/react/devsupport/interfaces/PackagerStatusCallback;", "setHotModuleReplacementEnabled", "isHotModuleReplacementEnabled", "setRemoteJSDebugEnabled", "isRemoteJSDebugEnabled", "setFpsDebugEnabled", "isFpsDebugEnabled", "toggleElementInspector", "downloadBundleResourceFromUrlSync", "Ljava/io/File;", "resourceURL", "outputFile", "registerErrorCustomizer", "errorCustomizer", "Lcom/facebook/react/devsupport/interfaces/ErrorCustomizer;", "processErrorCustomizers", "Landroid/util/Pair;", "errorInfo", "setPackagerLocationCustomizer", "packagerLocationCustomizer", "Lcom/facebook/react/devsupport/interfaces/DevSupportManager$PackagerLocationCustomizer;", "createSurfaceDelegate", "Lcom/facebook/react/common/SurfaceDelegate;", "moduleName", "openDebugger", "showPausedInDebuggerOverlay", "listener", "Lcom/facebook/react/devsupport/interfaces/DevSupportManager$PausedInDebuggerOverlayCommandListener;", "hidePausedInDebuggerOverlay", "setAdditionalOptionForPackager", "name", "value", "PackagerLocationCustomizer", "PausedInDebuggerOverlayCommandListener", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface DevSupportManager extends JSExceptionHandler {

    /* compiled from: DevSupportManager.kt */
    @Metadata(d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bæ\u0080\u0001\u0018\u00002\u00020\u0001J\u0012\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0006À\u0006\u0001"}, d2 = {"Lcom/facebook/react/devsupport/interfaces/DevSupportManager$PackagerLocationCustomizer;", "", "run", "", "callback", "Ljava/lang/Runnable;", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface PackagerLocationCustomizer {
        void run(Runnable callback);
    }

    /* compiled from: DevSupportManager.kt */
    @Metadata(d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H&ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0004À\u0006\u0001"}, d2 = {"Lcom/facebook/react/devsupport/interfaces/DevSupportManager$PausedInDebuggerOverlayCommandListener;", "", "onResume", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public interface PausedInDebuggerOverlayCommandListener {
        void onResume();
    }

    void addCustomDevOption(String optionName, DevOptionHandler optionHandler);

    View createRootView(String appKey);

    SurfaceDelegate createSurfaceDelegate(String moduleName);

    void destroyRootView(View rootView);

    File downloadBundleResourceFromUrlSync(String resourceURL, File outputFile);

    Activity getCurrentActivity();

    ReactContext getCurrentReactContext();

    DeveloperSettings getDevSettings();

    boolean getDevSupportEnabled();

    String getDownloadedJSBundleFile();

    String getJSBundleURLForRemoteDebugging();

    int getLastErrorCookie();

    StackFrame[] getLastErrorStack();

    String getLastErrorTitle();

    ErrorType getLastErrorType();

    RedBoxHandler getRedBoxHandler();

    String getSourceMapUrl();

    String getSourceUrl();

    void handleReloadJS();

    boolean hasUpToDateJSBundleInCache();

    void hidePausedInDebuggerOverlay();

    void hideRedboxDialog();

    void isPackagerRunning(PackagerStatusCallback callback);

    void loadSplitBundleFromServer(String bundlePath, DevSplitBundleCallback callback);

    void onNewReactContextCreated(ReactContext reactContext);

    void onReactInstanceDestroyed(ReactContext reactContext);

    void openDebugger();

    Pair<String, StackFrame[]> processErrorCustomizers(Pair<String, StackFrame[]> errorInfo);

    void registerErrorCustomizer(ErrorCustomizer errorCustomizer);

    void reloadJSFromServer(String bundleURL, BundleLoadCallback callback);

    void reloadSettings();

    void setAdditionalOptionForPackager(String name, String value);

    void setDevSupportEnabled(boolean z);

    void setFpsDebugEnabled(boolean isFpsDebugEnabled);

    void setHotModuleReplacementEnabled(boolean isHotModuleReplacementEnabled);

    void setPackagerLocationCustomizer(PackagerLocationCustomizer packagerLocationCustomizer);

    void setRemoteJSDebugEnabled(boolean isRemoteJSDebugEnabled);

    void showDevOptionsDialog();

    void showNewJSError(String message, ReadableArray details, int errorCookie);

    void showNewJavaError(String message, Throwable e);

    void showPausedInDebuggerOverlay(String message, PausedInDebuggerOverlayCommandListener listener);

    void startInspector();

    void stopInspector();

    void toggleElementInspector();
}
