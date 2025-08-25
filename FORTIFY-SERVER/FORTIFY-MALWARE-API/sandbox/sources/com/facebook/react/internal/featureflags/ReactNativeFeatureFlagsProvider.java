package com.facebook.react.internal.featureflags;

import kotlin.Metadata;

/* compiled from: ReactNativeFeatureFlagsProvider.kt */
@Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b-\bg\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H'J\b\u0010\u0004\u001a\u00020\u0003H'J\b\u0010\u0005\u001a\u00020\u0003H'J\b\u0010\u0006\u001a\u00020\u0003H'J\b\u0010\u0007\u001a\u00020\u0003H'J\b\u0010\b\u001a\u00020\u0003H'J\b\u0010\t\u001a\u00020\u0003H'J\b\u0010\n\u001a\u00020\u0003H'J\b\u0010\u000b\u001a\u00020\u0003H'J\b\u0010\f\u001a\u00020\u0003H'J\b\u0010\r\u001a\u00020\u0003H'J\b\u0010\u000e\u001a\u00020\u0003H'J\b\u0010\u000f\u001a\u00020\u0003H'J\b\u0010\u0010\u001a\u00020\u0003H'J\b\u0010\u0011\u001a\u00020\u0003H'J\b\u0010\u0012\u001a\u00020\u0003H'J\b\u0010\u0013\u001a\u00020\u0003H'J\b\u0010\u0014\u001a\u00020\u0003H'J\b\u0010\u0015\u001a\u00020\u0003H'J\b\u0010\u0016\u001a\u00020\u0003H'J\b\u0010\u0017\u001a\u00020\u0003H'J\b\u0010\u0018\u001a\u00020\u0003H'J\b\u0010\u0019\u001a\u00020\u0003H'J\b\u0010\u001a\u001a\u00020\u0003H'J\b\u0010\u001b\u001a\u00020\u0003H'J\b\u0010\u001c\u001a\u00020\u0003H'J\b\u0010\u001d\u001a\u00020\u0003H'J\b\u0010\u001e\u001a\u00020\u0003H'J\b\u0010\u001f\u001a\u00020\u0003H'J\b\u0010 \u001a\u00020\u0003H'J\b\u0010!\u001a\u00020\u0003H'J\b\u0010\"\u001a\u00020\u0003H'J\b\u0010#\u001a\u00020\u0003H'J\b\u0010$\u001a\u00020\u0003H'J\b\u0010%\u001a\u00020\u0003H'J\b\u0010&\u001a\u00020\u0003H'J\b\u0010'\u001a\u00020\u0003H'J\b\u0010(\u001a\u00020\u0003H'J\b\u0010)\u001a\u00020\u0003H'J\b\u0010*\u001a\u00020\u0003H'J\b\u0010+\u001a\u00020\u0003H'J\b\u0010,\u001a\u00020\u0003H'J\b\u0010-\u001a\u00020\u0003H'J\b\u0010.\u001a\u00020\u0003H'J\b\u0010/\u001a\u00020\u0003H'ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u00060À\u0006\u0001"}, d2 = {"Lcom/facebook/react/internal/featureflags/ReactNativeFeatureFlagsProvider;", "", "commonTestFlag", "", "completeReactInstanceCreationOnBgThreadOnAndroid", "disableEventLoopOnBridgeless", "disableMountItemReorderingAndroid", "enableAccumulatedUpdatesInRawPropsAndroid", "enableBridgelessArchitecture", "enableCppPropsIteratorSetter", "enableDeletionOfUnmountedViews", "enableEagerRootViewAttachment", "enableEventEmitterRetentionDuringGesturesOnAndroid", "enableFabricLogs", "enableFabricRenderer", "enableFixForViewCommandRace", "enableGranularShadowTreeStateReconciliation", "enableIOSViewClipToPaddingBox", "enableImagePrefetchingAndroid", "enableLayoutAnimationsOnAndroid", "enableLayoutAnimationsOnIOS", "enableLongTaskAPI", "enableNewBackgroundAndBorderDrawables", "enablePreciseSchedulingForPremountItemsOnAndroid", "enablePropsUpdateReconciliationAndroid", "enableReportEventPaintTime", "enableSynchronousStateUpdates", "enableUIConsistency", "enableViewRecycling", "excludeYogaFromRawProps", "fixDifferentiatorEmittingUpdatesWithWrongParentTag", "fixMappingOfEventPrioritiesBetweenFabricAndReact", "fixMountingCoordinatorReportedPendingTransactionsOnAndroid", "fuseboxEnabledRelease", "initEagerTurboModulesOnNativeModulesQueueAndroid", "lazyAnimationCallbacks", "loadVectorDrawablesOnImages", "traceTurboModulePromiseRejectionsOnAndroid", "useAlwaysAvailableJSErrorHandling", "useFabricInterop", "useImmediateExecutorInAndroidBridgeless", "useNativeViewConfigsInBridgelessMode", "useOptimisedViewPreallocationOnAndroid", "useOptimizedEventBatchingOnAndroid", "useRawPropsJsiValue", "useRuntimeShadowNodeReferenceUpdate", "useTurboModuleInterop", "useTurboModules", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public interface ReactNativeFeatureFlagsProvider {
    boolean commonTestFlag();

    boolean completeReactInstanceCreationOnBgThreadOnAndroid();

    boolean disableEventLoopOnBridgeless();

    boolean disableMountItemReorderingAndroid();

    boolean enableAccumulatedUpdatesInRawPropsAndroid();

    boolean enableBridgelessArchitecture();

    boolean enableCppPropsIteratorSetter();

    boolean enableDeletionOfUnmountedViews();

    boolean enableEagerRootViewAttachment();

    boolean enableEventEmitterRetentionDuringGesturesOnAndroid();

    boolean enableFabricLogs();

    boolean enableFabricRenderer();

    boolean enableFixForViewCommandRace();

    boolean enableGranularShadowTreeStateReconciliation();

    boolean enableIOSViewClipToPaddingBox();

    boolean enableImagePrefetchingAndroid();

    boolean enableLayoutAnimationsOnAndroid();

    boolean enableLayoutAnimationsOnIOS();

    boolean enableLongTaskAPI();

    boolean enableNewBackgroundAndBorderDrawables();

    boolean enablePreciseSchedulingForPremountItemsOnAndroid();

    boolean enablePropsUpdateReconciliationAndroid();

    boolean enableReportEventPaintTime();

    boolean enableSynchronousStateUpdates();

    boolean enableUIConsistency();

    boolean enableViewRecycling();

    boolean excludeYogaFromRawProps();

    boolean fixDifferentiatorEmittingUpdatesWithWrongParentTag();

    boolean fixMappingOfEventPrioritiesBetweenFabricAndReact();

    boolean fixMountingCoordinatorReportedPendingTransactionsOnAndroid();

    boolean fuseboxEnabledRelease();

    boolean initEagerTurboModulesOnNativeModulesQueueAndroid();

    boolean lazyAnimationCallbacks();

    boolean loadVectorDrawablesOnImages();

    boolean traceTurboModulePromiseRejectionsOnAndroid();

    boolean useAlwaysAvailableJSErrorHandling();

    boolean useFabricInterop();

    boolean useImmediateExecutorInAndroidBridgeless();

    boolean useNativeViewConfigsInBridgelessMode();

    boolean useOptimisedViewPreallocationOnAndroid();

    boolean useOptimizedEventBatchingOnAndroid();

    boolean useRawPropsJsiValue();

    boolean useRuntimeShadowNodeReferenceUpdate();

    boolean useTurboModuleInterop();

    boolean useTurboModules();
}
