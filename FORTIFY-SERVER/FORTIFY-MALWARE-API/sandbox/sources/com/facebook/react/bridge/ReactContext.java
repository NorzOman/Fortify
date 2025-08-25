package com.facebook.react.bridge;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import com.facebook.common.logging.FLog;
import com.facebook.infer.annotation.Assertions;
import com.facebook.react.bridge.interop.InteropModuleRegistry;
import com.facebook.react.bridge.queue.MessageQueueThread;
import com.facebook.react.bridge.queue.ReactQueueConfiguration;
import com.facebook.react.common.LifecycleState;
import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder;
import java.lang.ref.WeakReference;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArraySet;

/* loaded from: classes.dex */
public abstract class ReactContext extends ContextWrapper {
    private static final String TAG = "ReactContext";
    private final CopyOnWriteArraySet<ActivityEventListener> mActivityEventListeners;
    private WeakReference<Activity> mCurrentActivity;
    private JSExceptionHandler mExceptionHandlerWrapper;
    private LayoutInflater mInflater;
    protected InteropModuleRegistry mInteropModuleRegistry;
    private boolean mIsInitialized;
    private JSExceptionHandler mJSExceptionHandler;
    private MessageQueueThread mJSMessageQueueThread;
    private final CopyOnWriteArraySet<LifecycleEventListener> mLifecycleEventListeners;
    private LifecycleState mLifecycleState;
    private MessageQueueThread mNativeModulesMessageQueueThread;
    private ReactQueueConfiguration mQueueConfig;
    private MessageQueueThread mUiMessageQueueThread;
    private final CopyOnWriteArraySet<WindowFocusChangeListener> mWindowFocusEventListeners;

    public interface RCTDeviceEventEmitter extends JavaScriptModule {
        void emit(String str, Object obj);
    }

    public abstract void destroy();

    public abstract CatalystInstance getCatalystInstance();

    @Deprecated(since = "This method is deprecated, please use UIManagerHelper.getUIManager() instead.")
    public abstract UIManager getFabricUIManager();

    public abstract CallInvokerHolder getJSCallInvokerHolder();

    public abstract <T extends JavaScriptModule> T getJSModule(Class<T> cls);

    public abstract JavaScriptContextHolder getJavaScriptContextHolder();

    public abstract <T extends NativeModule> T getNativeModule(Class<T> cls);

    public abstract NativeModule getNativeModule(String str);

    public abstract Collection<NativeModule> getNativeModules();

    public abstract String getSourceURL();

    public abstract void handleException(Exception exc);

    @Deprecated
    public abstract boolean hasActiveCatalystInstance();

    public abstract boolean hasActiveReactInstance();

    @Deprecated
    public abstract boolean hasCatalystInstance();

    public abstract <T extends NativeModule> boolean hasNativeModule(Class<T> cls);

    public abstract boolean hasReactInstance();

    @Deprecated
    public abstract boolean isBridgeless();

    public abstract void registerSegment(int i, String str, Callback callback);

    public ReactContext(Context context) {
        super(context);
        this.mLifecycleEventListeners = new CopyOnWriteArraySet<>();
        this.mActivityEventListeners = new CopyOnWriteArraySet<>();
        this.mWindowFocusEventListeners = new CopyOnWriteArraySet<>();
        this.mLifecycleState = LifecycleState.BEFORE_CREATE;
        this.mIsInitialized = false;
    }

    protected void initializeFromOther(ReactContext reactContext) {
        if (reactContext.hasReactInstance()) {
            initializeMessageQueueThreads(reactContext.mQueueConfig);
        }
        this.mInteropModuleRegistry = reactContext.mInteropModuleRegistry;
    }

    public synchronized void initializeMessageQueueThreads(ReactQueueConfiguration reactQueueConfiguration) {
        FLog.d(TAG, "initializeMessageQueueThreads() is called.");
        if (this.mUiMessageQueueThread != null || this.mNativeModulesMessageQueueThread != null || this.mJSMessageQueueThread != null) {
            throw new IllegalStateException("Message queue threads already initialized");
        }
        this.mQueueConfig = reactQueueConfiguration;
        this.mUiMessageQueueThread = reactQueueConfiguration.getUIQueueThread();
        this.mNativeModulesMessageQueueThread = reactQueueConfiguration.getNativeModulesQueueThread();
        MessageQueueThread jSQueueThread = reactQueueConfiguration.getJSQueueThread();
        this.mJSMessageQueueThread = jSQueueThread;
        if (this.mUiMessageQueueThread == null) {
            throw new IllegalStateException("UI thread is null");
        }
        if (this.mNativeModulesMessageQueueThread == null) {
            throw new IllegalStateException("NativeModules thread is null");
        }
        if (jSQueueThread == null) {
            throw new IllegalStateException("JavaScript thread is null");
        }
        this.mIsInitialized = true;
    }

    protected void initializeInteropModules() {
        this.mInteropModuleRegistry = new InteropModuleRegistry();
    }

    public void resetPerfStats() {
        MessageQueueThread messageQueueThread = this.mNativeModulesMessageQueueThread;
        if (messageQueueThread != null) {
            messageQueueThread.resetPerfStats();
        }
        MessageQueueThread messageQueueThread2 = this.mJSMessageQueueThread;
        if (messageQueueThread2 != null) {
            messageQueueThread2.resetPerfStats();
        }
    }

    public void setJSExceptionHandler(JSExceptionHandler jSExceptionHandler) {
        this.mJSExceptionHandler = jSExceptionHandler;
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public Object getSystemService(String str) {
        if ("layout_inflater".equals(str)) {
            if (this.mInflater == null) {
                this.mInflater = LayoutInflater.from(getBaseContext()).cloneInContext(this);
            }
            return this.mInflater;
        }
        return getBaseContext().getSystemService(str);
    }

    public void emitDeviceEvent(String str, Object obj) {
        RCTDeviceEventEmitter rCTDeviceEventEmitter = (RCTDeviceEventEmitter) getJSModule(RCTDeviceEventEmitter.class);
        if (rCTDeviceEventEmitter != null) {
            rCTDeviceEventEmitter.emit(str, obj);
        }
    }

    public void emitDeviceEvent(String str) {
        emitDeviceEvent(str, null);
    }

    public LifecycleState getLifecycleState() {
        return this.mLifecycleState;
    }

    public void addLifecycleEventListener(final LifecycleEventListener lifecycleEventListener) {
        int i;
        this.mLifecycleEventListeners.add(lifecycleEventListener);
        if ((!hasActiveReactInstance() && !isBridgeless()) || (i = AnonymousClass2.$SwitchMap$com$facebook$react$common$LifecycleState[this.mLifecycleState.ordinal()]) == 1 || i == 2) {
            return;
        }
        if (i == 3) {
            runOnUiQueueThread(new Runnable() { // from class: com.facebook.react.bridge.ReactContext.1
                @Override // java.lang.Runnable
                public void run() {
                    if (ReactContext.this.mLifecycleEventListeners.contains(lifecycleEventListener)) {
                        try {
                            lifecycleEventListener.onHostResume();
                        } catch (RuntimeException e) {
                            ReactContext.this.handleException(e);
                        }
                    }
                }
            });
            return;
        }
        throw new IllegalStateException("Unhandled lifecycle state.");
    }

    /* renamed from: com.facebook.react.bridge.ReactContext$2, reason: invalid class name */
    static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$com$facebook$react$common$LifecycleState;

        static {
            int[] iArr = new int[LifecycleState.values().length];
            $SwitchMap$com$facebook$react$common$LifecycleState = iArr;
            try {
                iArr[LifecycleState.BEFORE_CREATE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$facebook$react$common$LifecycleState[LifecycleState.BEFORE_RESUME.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$facebook$react$common$LifecycleState[LifecycleState.RESUMED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    public void removeLifecycleEventListener(LifecycleEventListener lifecycleEventListener) {
        this.mLifecycleEventListeners.remove(lifecycleEventListener);
    }

    public void addActivityEventListener(ActivityEventListener activityEventListener) {
        this.mActivityEventListeners.add(activityEventListener);
    }

    public void removeActivityEventListener(ActivityEventListener activityEventListener) {
        this.mActivityEventListeners.remove(activityEventListener);
    }

    public void addWindowFocusChangeListener(WindowFocusChangeListener windowFocusChangeListener) {
        this.mWindowFocusEventListeners.add(windowFocusChangeListener);
    }

    public void removeWindowFocusChangeListener(WindowFocusChangeListener windowFocusChangeListener) {
        this.mWindowFocusEventListeners.remove(windowFocusChangeListener);
    }

    public void onHostResume(Activity activity) {
        this.mLifecycleState = LifecycleState.RESUMED;
        this.mCurrentActivity = new WeakReference<>(activity);
        ReactMarker.logMarker(ReactMarkerConstants.ON_HOST_RESUME_START);
        Iterator<LifecycleEventListener> it = this.mLifecycleEventListeners.iterator();
        while (it.hasNext()) {
            try {
                it.next().onHostResume();
            } catch (RuntimeException e) {
                handleException(e);
            }
        }
        ReactMarker.logMarker(ReactMarkerConstants.ON_HOST_RESUME_END);
    }

    public void onUserLeaveHint(Activity activity) {
        ReactMarker.logMarker(ReactMarkerConstants.ON_USER_LEAVE_HINT_START);
        Iterator<ActivityEventListener> it = this.mActivityEventListeners.iterator();
        while (it.hasNext()) {
            try {
                it.next().onUserLeaveHint(activity);
            } catch (RuntimeException e) {
                handleException(e);
            }
        }
        ReactMarker.logMarker(ReactMarkerConstants.ON_USER_LEAVE_HINT_END);
    }

    public void onNewIntent(Activity activity, Intent intent) {
        UiThreadUtil.assertOnUiThread();
        this.mCurrentActivity = new WeakReference<>(activity);
        Iterator<ActivityEventListener> it = this.mActivityEventListeners.iterator();
        while (it.hasNext()) {
            try {
                it.next().onNewIntent(intent);
            } catch (RuntimeException e) {
                handleException(e);
            }
        }
    }

    public void onHostPause() {
        this.mLifecycleState = LifecycleState.BEFORE_RESUME;
        ReactMarker.logMarker(ReactMarkerConstants.ON_HOST_PAUSE_START);
        Iterator<LifecycleEventListener> it = this.mLifecycleEventListeners.iterator();
        while (it.hasNext()) {
            try {
                it.next().onHostPause();
            } catch (RuntimeException e) {
                handleException(e);
            }
        }
        ReactMarker.logMarker(ReactMarkerConstants.ON_HOST_PAUSE_END);
    }

    public void onHostDestroy() {
        onHostDestroyImpl();
        this.mCurrentActivity = null;
    }

    public void onHostDestroy(boolean z) {
        if (!z) {
            onHostDestroy();
        } else {
            onHostDestroyImpl();
        }
    }

    private void onHostDestroyImpl() {
        UiThreadUtil.assertOnUiThread();
        this.mLifecycleState = LifecycleState.BEFORE_CREATE;
        Iterator<LifecycleEventListener> it = this.mLifecycleEventListeners.iterator();
        while (it.hasNext()) {
            try {
                it.next().onHostDestroy();
            } catch (RuntimeException e) {
                handleException(e);
            }
        }
    }

    public void onActivityResult(Activity activity, int i, int i2, Intent intent) {
        Iterator<ActivityEventListener> it = this.mActivityEventListeners.iterator();
        while (it.hasNext()) {
            try {
                it.next().onActivityResult(activity, i, i2, intent);
            } catch (RuntimeException e) {
                handleException(e);
            }
        }
    }

    public void onWindowFocusChange(boolean z) {
        UiThreadUtil.assertOnUiThread();
        Iterator<WindowFocusChangeListener> it = this.mWindowFocusEventListeners.iterator();
        while (it.hasNext()) {
            try {
                it.next().onWindowFocusChange(z);
            } catch (RuntimeException e) {
                handleException(e);
            }
        }
    }

    public void assertOnUiQueueThread() {
        ((MessageQueueThread) Assertions.assertNotNull(this.mUiMessageQueueThread)).assertIsOnThread();
    }

    public boolean isOnUiQueueThread() {
        return ((MessageQueueThread) Assertions.assertNotNull(this.mUiMessageQueueThread)).isOnThread();
    }

    public void runOnUiQueueThread(Runnable runnable) {
        ((MessageQueueThread) Assertions.assertNotNull(this.mUiMessageQueueThread)).runOnQueue(runnable);
    }

    public void assertOnNativeModulesQueueThread() {
        if (!this.mIsInitialized) {
            throw new IllegalStateException("Tried to call assertOnNativeModulesQueueThread() on an uninitialized ReactContext");
        }
        ((MessageQueueThread) Assertions.assertNotNull(this.mNativeModulesMessageQueueThread)).assertIsOnThread();
    }

    public void assertOnNativeModulesQueueThread(String str) {
        if (!this.mIsInitialized) {
            throw new IllegalStateException("Tried to call assertOnNativeModulesQueueThread(message) on an uninitialized ReactContext");
        }
        ((MessageQueueThread) Assertions.assertNotNull(this.mNativeModulesMessageQueueThread)).assertIsOnThread(str);
    }

    public boolean isOnNativeModulesQueueThread() {
        return ((MessageQueueThread) Assertions.assertNotNull(this.mNativeModulesMessageQueueThread)).isOnThread();
    }

    public void runOnNativeModulesQueueThread(Runnable runnable) {
        ((MessageQueueThread) Assertions.assertNotNull(this.mNativeModulesMessageQueueThread)).runOnQueue(runnable);
    }

    public void assertOnJSQueueThread() {
        ((MessageQueueThread) Assertions.assertNotNull(this.mJSMessageQueueThread)).assertIsOnThread();
    }

    public boolean isOnJSQueueThread() {
        return ((MessageQueueThread) Assertions.assertNotNull(this.mJSMessageQueueThread)).isOnThread();
    }

    public boolean runOnJSQueueThread(Runnable runnable) {
        return ((MessageQueueThread) Assertions.assertNotNull(this.mJSMessageQueueThread)).runOnQueue(runnable);
    }

    public MessageQueueThread getJSMessageQueueThread() {
        return this.mJSMessageQueueThread;
    }

    public MessageQueueThread getNativeModulesMessageQueueThread() {
        return this.mNativeModulesMessageQueueThread;
    }

    public MessageQueueThread getUiMessageQueueThread() {
        return this.mUiMessageQueueThread;
    }

    public class ExceptionHandlerWrapper implements JSExceptionHandler {
        public ExceptionHandlerWrapper() {
        }

        @Override // com.facebook.react.bridge.JSExceptionHandler
        public void handleException(Exception exc) {
            ReactContext.this.handleException(exc);
        }
    }

    public JSExceptionHandler getExceptionHandler() {
        if (this.mExceptionHandlerWrapper == null) {
            this.mExceptionHandlerWrapper = new ExceptionHandlerWrapper();
        }
        return this.mExceptionHandlerWrapper;
    }

    public JSExceptionHandler getJSExceptionHandler() {
        return this.mJSExceptionHandler;
    }

    public boolean hasCurrentActivity() {
        WeakReference<Activity> weakReference = this.mCurrentActivity;
        return (weakReference == null || weakReference.get() == null) ? false : true;
    }

    public boolean startActivityForResult(Intent intent, int i, Bundle bundle) {
        Activity currentActivity = getCurrentActivity();
        if (currentActivity == null) {
            return false;
        }
        currentActivity.startActivityForResult(intent, i, bundle);
        return true;
    }

    public Activity getCurrentActivity() {
        WeakReference<Activity> weakReference = this.mCurrentActivity;
        if (weakReference == null) {
            return null;
        }
        return weakReference.get();
    }

    public <T extends JavaScriptModule> void internal_registerInteropModule(Class<T> cls, Object obj) {
        InteropModuleRegistry interopModuleRegistry = this.mInteropModuleRegistry;
        if (interopModuleRegistry != null) {
            interopModuleRegistry.registerInteropModule(cls, obj);
        }
    }
}
