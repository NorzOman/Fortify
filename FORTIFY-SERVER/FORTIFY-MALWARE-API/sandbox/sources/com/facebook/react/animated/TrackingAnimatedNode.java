package com.facebook.react.animated;

import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.ReadableMap;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: TrackingAnimatedNode.kt */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\b\u0000\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0004\b\u0006\u0010\u0007J\b\u0010\u000e\u001a\u00020\u000fH\u0016J\b\u0010\u0010\u001a\u00020\u0011H\u0016R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\tX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u000bX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\u000bX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\r\u001a\u00020\u000bX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0012"}, d2 = {"Lcom/facebook/react/animated/TrackingAnimatedNode;", "Lcom/facebook/react/animated/AnimatedNode;", "config", "Lcom/facebook/react/bridge/ReadableMap;", "nativeAnimatedNodesManager", "Lcom/facebook/react/animated/NativeAnimatedNodesManager;", "<init>", "(Lcom/facebook/react/bridge/ReadableMap;Lcom/facebook/react/animated/NativeAnimatedNodesManager;)V", "animationConfig", "Lcom/facebook/react/bridge/JavaOnlyMap;", "animationId", "", "toValueNode", "valueNode", "update", "", "prettyPrint", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class TrackingAnimatedNode extends AnimatedNode {
    private final JavaOnlyMap animationConfig;
    private final int animationId;
    private final NativeAnimatedNodesManager nativeAnimatedNodesManager;
    private final int toValueNode;
    private final int valueNode;

    public TrackingAnimatedNode(ReadableMap config, NativeAnimatedNodesManager nativeAnimatedNodesManager) {
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(nativeAnimatedNodesManager, "nativeAnimatedNodesManager");
        this.nativeAnimatedNodesManager = nativeAnimatedNodesManager;
        this.animationConfig = JavaOnlyMap.INSTANCE.deepClone(config.getMap("animationConfig"));
        this.animationId = config.getInt("animationId");
        this.toValueNode = config.getInt("toValue");
        this.valueNode = config.getInt("value");
    }

    @Override // com.facebook.react.animated.AnimatedNode
    public void update() {
        AnimatedNode nodeById = this.nativeAnimatedNodesManager.getNodeById(this.toValueNode);
        ValueAnimatedNode valueAnimatedNode = nodeById instanceof ValueAnimatedNode ? (ValueAnimatedNode) nodeById : null;
        if (valueAnimatedNode != null) {
            this.animationConfig.putDouble("toValue", valueAnimatedNode.getValue());
        } else {
            this.animationConfig.putNull("toValue");
        }
        this.nativeAnimatedNodesManager.startAnimatingNode(this.animationId, this.valueNode, this.animationConfig, null);
    }

    @Override // com.facebook.react.animated.AnimatedNode
    public String prettyPrint() {
        return "TrackingAnimatedNode[" + this.tag + "]: animationID: " + this.animationId + " toValueNode: " + this.toValueNode + " valueNode: " + this.valueNode + " animationConfig: " + this.animationConfig;
    }
}
