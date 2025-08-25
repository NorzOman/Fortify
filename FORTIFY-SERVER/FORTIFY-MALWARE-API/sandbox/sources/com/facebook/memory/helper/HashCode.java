package com.facebook.memory.helper;

import com.facebook.react.animated.InterpolationAnimatedNode;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;

/* compiled from: HashCode.kt */
@Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003J\u001a\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00052\b\u0010\u0007\u001a\u0004\u0018\u00010\u0001H\u0007¨\u0006\b"}, d2 = {"Lcom/facebook/memory/helper/HashCode;", "", "<init>", "()V", InterpolationAnimatedNode.EXTRAPOLATE_TYPE_EXTEND, "", "current", "obj", "fbcore_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class HashCode {
    public static final HashCode INSTANCE = new HashCode();

    private HashCode() {
    }

    @JvmStatic
    public static final int extend(int current, Object obj) {
        return (current * 31) + (obj != null ? obj.hashCode() : 0);
    }
}
