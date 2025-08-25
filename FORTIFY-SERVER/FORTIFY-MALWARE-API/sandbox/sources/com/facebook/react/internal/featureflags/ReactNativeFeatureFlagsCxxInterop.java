package com.facebook.react.internal.featureflags;

import com.facebook.soloader.SoLoader;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: ReactNativeFeatureFlagsCxxInterop.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b-\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\bÇ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\t\u0010\u0004\u001a\u00020\u0005H\u0087 J\t\u0010\u0006\u001a\u00020\u0005H\u0087 J\t\u0010\u0007\u001a\u00020\u0005H\u0087 J\t\u0010\b\u001a\u00020\u0005H\u0087 J\t\u0010\t\u001a\u00020\u0005H\u0087 J\t\u0010\n\u001a\u00020\u0005H\u0087 J\t\u0010\u000b\u001a\u00020\u0005H\u0087 J\t\u0010\f\u001a\u00020\u0005H\u0087 J\t\u0010\r\u001a\u00020\u0005H\u0087 J\t\u0010\u000e\u001a\u00020\u0005H\u0087 J\t\u0010\u000f\u001a\u00020\u0005H\u0087 J\t\u0010\u0010\u001a\u00020\u0005H\u0087 J\t\u0010\u0011\u001a\u00020\u0005H\u0087 J\t\u0010\u0012\u001a\u00020\u0005H\u0087 J\t\u0010\u0013\u001a\u00020\u0005H\u0087 J\t\u0010\u0014\u001a\u00020\u0005H\u0087 J\t\u0010\u0015\u001a\u00020\u0005H\u0087 J\t\u0010\u0016\u001a\u00020\u0005H\u0087 J\t\u0010\u0017\u001a\u00020\u0005H\u0087 J\t\u0010\u0018\u001a\u00020\u0005H\u0087 J\t\u0010\u0019\u001a\u00020\u0005H\u0087 J\t\u0010\u001a\u001a\u00020\u0005H\u0087 J\t\u0010\u001b\u001a\u00020\u0005H\u0087 J\t\u0010\u001c\u001a\u00020\u0005H\u0087 J\t\u0010\u001d\u001a\u00020\u0005H\u0087 J\t\u0010\u001e\u001a\u00020\u0005H\u0087 J\t\u0010\u001f\u001a\u00020\u0005H\u0087 J\t\u0010 \u001a\u00020\u0005H\u0087 J\t\u0010!\u001a\u00020\u0005H\u0087 J\t\u0010\"\u001a\u00020\u0005H\u0087 J\t\u0010#\u001a\u00020\u0005H\u0087 J\t\u0010$\u001a\u00020\u0005H\u0087 J\t\u0010%\u001a\u00020\u0005H\u0087 J\t\u0010&\u001a\u00020\u0005H\u0087 J\t\u0010'\u001a\u00020\u0005H\u0087 J\t\u0010(\u001a\u00020\u0005H\u0087 J\t\u0010)\u001a\u00020\u0005H\u0087 J\t\u0010*\u001a\u00020\u0005H\u0087 J\t\u0010+\u001a\u00020\u0005H\u0087 J\t\u0010,\u001a\u00020\u0005H\u0087 J\t\u0010-\u001a\u00020\u0005H\u0087 J\t\u0010.\u001a\u00020\u0005H\u0087 J\t\u0010/\u001a\u00020\u0005H\u0087 J\t\u00100\u001a\u00020\u0005H\u0087 J\t\u00101\u001a\u00020\u0005H\u0087 J\u0011\u00102\u001a\u0002032\u0006\u00104\u001a\u00020\u0001H\u0087 J\t\u00105\u001a\u000203H\u0087 J\u0013\u00106\u001a\u0004\u0018\u0001072\u0006\u00104\u001a\u00020\u0001H\u0087 ¨\u00068"}, d2 = {"Lcom/facebook/react/internal/featureflags/ReactNativeFeatureFlagsCxxInterop;", "", "<init>", "()V", "commonTestFlag", "", "completeReactInstanceCreationOnBgThreadOnAndroid", "disableEventLoopOnBridgeless", "disableMountItemReorderingAndroid", "enableAccumulatedUpdatesInRawPropsAndroid", "enableBridgelessArchitecture", "enableCppPropsIteratorSetter", "enableDeletionOfUnmountedViews", "enableEagerRootViewAttachment", "enableEventEmitterRetentionDuringGesturesOnAndroid", "enableFabricLogs", "enableFabricRenderer", "enableFixForViewCommandRace", "enableGranularShadowTreeStateReconciliation", "enableIOSViewClipToPaddingBox", "enableImagePrefetchingAndroid", "enableLayoutAnimationsOnAndroid", "enableLayoutAnimationsOnIOS", "enableLongTaskAPI", "enableNewBackgroundAndBorderDrawables", "enablePreciseSchedulingForPremountItemsOnAndroid", "enablePropsUpdateReconciliationAndroid", "enableReportEventPaintTime", "enableSynchronousStateUpdates", "enableUIConsistency", "enableViewRecycling", "excludeYogaFromRawProps", "fixDifferentiatorEmittingUpdatesWithWrongParentTag", "fixMappingOfEventPrioritiesBetweenFabricAndReact", "fixMountingCoordinatorReportedPendingTransactionsOnAndroid", "fuseboxEnabledRelease", "initEagerTurboModulesOnNativeModulesQueueAndroid", "lazyAnimationCallbacks", "loadVectorDrawablesOnImages", "traceTurboModulePromiseRejectionsOnAndroid", "useAlwaysAvailableJSErrorHandling", "useFabricInterop", "useImmediateExecutorInAndroidBridgeless", "useNativeViewConfigsInBridgelessMode", "useOptimisedViewPreallocationOnAndroid", "useOptimizedEventBatchingOnAndroid", "useRawPropsJsiValue", "useRuntimeShadowNodeReferenceUpdate", "useTurboModuleInterop", "useTurboModules", "override", "", "provider", "dangerouslyReset", "dangerouslyForceOverride", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class ReactNativeFeatureFlagsCxxInterop {
    public static final ReactNativeFeatureFlagsCxxInterop INSTANCE = new ReactNativeFeatureFlagsCxxInterop();

    @JvmStatic
    public static final native boolean commonTestFlag();

    @JvmStatic
    public static final native boolean completeReactInstanceCreationOnBgThreadOnAndroid();

    @JvmStatic
    public static final native String dangerouslyForceOverride(Object provider);

    @JvmStatic
    public static final native void dangerouslyReset();

    @JvmStatic
    public static final native boolean disableEventLoopOnBridgeless();

    @JvmStatic
    public static final native boolean disableMountItemReorderingAndroid();

    @JvmStatic
    public static final native boolean enableAccumulatedUpdatesInRawPropsAndroid();

    @JvmStatic
    public static final native boolean enableBridgelessArchitecture();

    @JvmStatic
    public static final native boolean enableCppPropsIteratorSetter();

    @JvmStatic
    public static final native boolean enableDeletionOfUnmountedViews();

    @JvmStatic
    public static final native boolean enableEagerRootViewAttachment();

    @JvmStatic
    public static final native boolean enableEventEmitterRetentionDuringGesturesOnAndroid();

    @JvmStatic
    public static final native boolean enableFabricLogs();

    @JvmStatic
    public static final native boolean enableFabricRenderer();

    @JvmStatic
    public static final native boolean enableFixForViewCommandRace();

    @JvmStatic
    public static final native boolean enableGranularShadowTreeStateReconciliation();

    @JvmStatic
    public static final native boolean enableIOSViewClipToPaddingBox();

    @JvmStatic
    public static final native boolean enableImagePrefetchingAndroid();

    @JvmStatic
    public static final native boolean enableLayoutAnimationsOnAndroid();

    @JvmStatic
    public static final native boolean enableLayoutAnimationsOnIOS();

    @JvmStatic
    public static final native boolean enableLongTaskAPI();

    @JvmStatic
    public static final native boolean enableNewBackgroundAndBorderDrawables();

    @JvmStatic
    public static final native boolean enablePreciseSchedulingForPremountItemsOnAndroid();

    @JvmStatic
    public static final native boolean enablePropsUpdateReconciliationAndroid();

    @JvmStatic
    public static final native boolean enableReportEventPaintTime();

    @JvmStatic
    public static final native boolean enableSynchronousStateUpdates();

    @JvmStatic
    public static final native boolean enableUIConsistency();

    @JvmStatic
    public static final native boolean enableViewRecycling();

    @JvmStatic
    public static final native boolean excludeYogaFromRawProps();

    @JvmStatic
    public static final native boolean fixDifferentiatorEmittingUpdatesWithWrongParentTag();

    @JvmStatic
    public static final native boolean fixMappingOfEventPrioritiesBetweenFabricAndReact();

    @JvmStatic
    public static final native boolean fixMountingCoordinatorReportedPendingTransactionsOnAndroid();

    @JvmStatic
    public static final native boolean fuseboxEnabledRelease();

    @JvmStatic
    public static final native boolean initEagerTurboModulesOnNativeModulesQueueAndroid();

    @JvmStatic
    public static final native boolean lazyAnimationCallbacks();

    @JvmStatic
    public static final native boolean loadVectorDrawablesOnImages();

    @JvmStatic
    public static final native void override(Object provider);

    @JvmStatic
    public static final native boolean traceTurboModulePromiseRejectionsOnAndroid();

    @JvmStatic
    public static final native boolean useAlwaysAvailableJSErrorHandling();

    @JvmStatic
    public static final native boolean useFabricInterop();

    @JvmStatic
    public static final native boolean useImmediateExecutorInAndroidBridgeless();

    @JvmStatic
    public static final native boolean useNativeViewConfigsInBridgelessMode();

    @JvmStatic
    public static final native boolean useOptimisedViewPreallocationOnAndroid();

    @JvmStatic
    public static final native boolean useOptimizedEventBatchingOnAndroid();

    @JvmStatic
    public static final native boolean useRawPropsJsiValue();

    @JvmStatic
    public static final native boolean useRuntimeShadowNodeReferenceUpdate();

    @JvmStatic
    public static final native boolean useTurboModuleInterop();

    @JvmStatic
    public static final native boolean useTurboModules();

    private ReactNativeFeatureFlagsCxxInterop() {
    }

    static {
        SoLoader.loadLibrary("react_featureflagsjni");
    }
}
