package com.facebook.react.uimanager.layoutanimation;

import android.view.View;
import android.view.animation.Animation;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: LayoutUpdateAnimation.kt */
@Metadata(d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0006\b\u0000\u0018\u0000 \u00112\u00020\u0001:\u0001\u0011B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\r\u0010\u0004\u001a\u00020\u0005H\u0010¢\u0006\u0002\b\u0006J7\u0010\u0007\u001a\u0004\u0018\u00010\b2\u0006\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\f2\u0006\u0010\u000e\u001a\u00020\f2\u0006\u0010\u000f\u001a\u00020\fH\u0010¢\u0006\u0002\b\u0010¨\u0006\u0012"}, d2 = {"Lcom/facebook/react/uimanager/layoutanimation/LayoutUpdateAnimation;", "Lcom/facebook/react/uimanager/layoutanimation/AbstractLayoutAnimation;", "<init>", "()V", "isValid", "", "isValid$ReactAndroid_release", "createAnimationImpl", "Landroid/view/animation/Animation;", "view", "Landroid/view/View;", "x", "", "y", "width", "height", "createAnimationImpl$ReactAndroid_release", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class LayoutUpdateAnimation extends AbstractLayoutAnimation {
    private static final Companion Companion = new Companion(null);
    private static final boolean USE_TRANSLATE_ANIMATION = false;

    @Override // com.facebook.react.uimanager.layoutanimation.AbstractLayoutAnimation
    /* renamed from: isValid$ReactAndroid_release, reason: merged with bridge method [inline-methods] */
    public boolean isValid() {
        return this.mDurationMs > 0;
    }

    @Override // com.facebook.react.uimanager.layoutanimation.AbstractLayoutAnimation
    /* renamed from: createAnimationImpl$ReactAndroid_release, reason: merged with bridge method [inline-methods] */
    public Animation createAnimationImpl(View view, int x, int y, int width, int height) {
        Intrinsics.checkNotNullParameter(view, "view");
        boolean z = (((int) view.getX()) == x && ((int) view.getY()) == y) ? false : true;
        boolean z2 = (view.getWidth() == width && view.getHeight() == height) ? false : true;
        if (z || z2) {
            return new PositionAndSizeAnimation(view, x, y, width, height);
        }
        return null;
    }

    /* compiled from: LayoutUpdateAnimation.kt */
    @Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\b\u0082\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T¢\u0006\u0002\n\u0000¨\u0006\u0006"}, d2 = {"Lcom/facebook/react/uimanager/layoutanimation/LayoutUpdateAnimation$Companion;", "", "<init>", "()V", "USE_TRANSLATE_ANIMATION", "", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
    private static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }
}
