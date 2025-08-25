package com.facebook.react.animated;

import com.facebook.react.bridge.ReadableMap;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* compiled from: ValueAnimatedNode.kt */
@Metadata(d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0006\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0000\b\u0016\u0018\u00002\u00020\u0001B\u0013\u0012\n\b\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\u000b\u001a\u00020\u0007J\n\u0010\f\u001a\u0004\u0018\u00010\rH\u0016J\u0006\u0010\u000e\u001a\u00020\u000fJ\u0006\u0010\u0010\u001a\u00020\u000fJ\u0006\u0010\u0011\u001a\u00020\u000fJ\u0010\u0010\u0012\u001a\u00020\u000f2\b\u0010\u0013\u001a\u0004\u0018\u00010\nJ\b\u0010\u0014\u001a\u00020\u0015H\u0016R\u0012\u0010\u0006\u001a\u00020\u00078\u0000@\u0000X\u0081\u000e¢\u0006\u0002\n\u0000R\u0012\u0010\b\u001a\u00020\u00078\u0000@\u0000X\u0081\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\t\u001a\u0004\u0018\u00010\nX\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u0016"}, d2 = {"Lcom/facebook/react/animated/ValueAnimatedNode;", "Lcom/facebook/react/animated/AnimatedNode;", "config", "Lcom/facebook/react/bridge/ReadableMap;", "<init>", "(Lcom/facebook/react/bridge/ReadableMap;)V", "nodeValue", "", "offset", "valueListener", "Lcom/facebook/react/animated/AnimatedNodeValueListener;", "getValue", "getAnimatedObject", "", "flattenOffset", "", "extractOffset", "onValueUpdate", "setValueListener", "listener", "prettyPrint", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public class ValueAnimatedNode extends AnimatedNode {
    public double nodeValue;
    public double offset;
    private AnimatedNodeValueListener valueListener;

    /* JADX WARN: Multi-variable type inference failed */
    public ValueAnimatedNode() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public Object getAnimatedObject() {
        return null;
    }

    public ValueAnimatedNode(ReadableMap readableMap) {
        this.nodeValue = readableMap != null ? readableMap.getDouble("value") : Double.NaN;
        this.offset = readableMap != null ? readableMap.getDouble("offset") : 0.0d;
    }

    public /* synthetic */ ValueAnimatedNode(ReadableMap readableMap, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : readableMap);
    }

    public final double getValue() {
        if (Double.isNaN(this.offset + this.nodeValue)) {
            update();
        }
        return this.offset + this.nodeValue;
    }

    public final void flattenOffset() {
        this.nodeValue += this.offset;
        this.offset = 0.0d;
    }

    public final void extractOffset() {
        this.offset += this.nodeValue;
        this.nodeValue = 0.0d;
    }

    public final void onValueUpdate() {
        AnimatedNodeValueListener animatedNodeValueListener = this.valueListener;
        if (animatedNodeValueListener != null) {
            animatedNodeValueListener.onValueUpdate(getValue());
        }
    }

    public final void setValueListener(AnimatedNodeValueListener listener) {
        this.valueListener = listener;
    }

    @Override // com.facebook.react.animated.AnimatedNode
    public String prettyPrint() {
        return "ValueAnimatedNode[" + this.tag + "]: value: " + this.nodeValue + " offset: " + this.offset;
    }
}
