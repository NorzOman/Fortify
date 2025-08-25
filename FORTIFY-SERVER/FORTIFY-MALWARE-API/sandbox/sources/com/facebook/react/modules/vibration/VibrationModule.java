package com.facebook.react.modules.vibration;

import android.os.Build;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;
import com.facebook.fbreact.specs.NativeVibrationSpec;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.module.annotations.ReactModule;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: VibrationModule.kt */
@ReactModule(name = "Vibration")
@Metadata(d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u0006\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0001\u0018\u0000 \u00112\u00020\u0001:\u0001\u0011B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0010\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH\u0016J\u0018\u0010\n\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\tH\u0016J\b\u0010\u000e\u001a\u00020\u0007H\u0016J\n\u0010\u000f\u001a\u0004\u0018\u00010\u0010H\u0002¨\u0006\u0012"}, d2 = {"Lcom/facebook/react/modules/vibration/VibrationModule;", "Lcom/facebook/fbreact/specs/NativeVibrationSpec;", "reactContext", "Lcom/facebook/react/bridge/ReactApplicationContext;", "<init>", "(Lcom/facebook/react/bridge/ReactApplicationContext;)V", "vibrate", "", "durationDouble", "", "vibrateByPattern", "pattern", "Lcom/facebook/react/bridge/ReadableArray;", "repeatDouble", "cancel", "getVibrator", "Landroid/os/Vibrator;", "Companion", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class VibrationModule extends NativeVibrationSpec {
    public static final String NAME = "Vibration";

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public VibrationModule(ReactApplicationContext reactContext) {
        super(reactContext);
        Intrinsics.checkNotNullParameter(reactContext, "reactContext");
    }

    @Override // com.facebook.fbreact.specs.NativeVibrationSpec
    public void vibrate(double durationDouble) {
        int i = (int) durationDouble;
        Vibrator vibrator = getVibrator();
        if (vibrator == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            vibrator.vibrate(VibrationEffect.createOneShot(i, -1));
        } else {
            vibrator.vibrate(i);
        }
    }

    @Override // com.facebook.fbreact.specs.NativeVibrationSpec
    public void vibrateByPattern(ReadableArray pattern, double repeatDouble) {
        Intrinsics.checkNotNullParameter(pattern, "pattern");
        int i = (int) repeatDouble;
        Vibrator vibrator = getVibrator();
        if (vibrator == null) {
            return;
        }
        long[] jArr = new long[pattern.size()];
        int size = pattern.size();
        for (int i2 = 0; i2 < size; i2++) {
            jArr[i2] = pattern.getInt(i2);
        }
        if (Build.VERSION.SDK_INT >= 26) {
            vibrator.vibrate(VibrationEffect.createWaveform(jArr, i));
        } else {
            vibrator.vibrate(jArr, i);
        }
    }

    @Override // com.facebook.fbreact.specs.NativeVibrationSpec
    public void cancel() {
        Vibrator vibrator = getVibrator();
        if (vibrator != null) {
            vibrator.cancel();
        }
    }

    private final Vibrator getVibrator() {
        if (Build.VERSION.SDK_INT >= 31) {
            VibratorManager vibratorManager = (VibratorManager) getReactApplicationContext().getSystemService("vibrator_manager");
            if (vibratorManager != null) {
                return vibratorManager.getDefaultVibrator();
            }
            return null;
        }
        return (Vibrator) getReactApplicationContext().getSystemService("vibrator");
    }
}
