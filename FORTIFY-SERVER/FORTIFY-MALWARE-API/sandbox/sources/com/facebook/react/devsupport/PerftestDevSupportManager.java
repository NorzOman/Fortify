package com.facebook.react.devsupport;

import android.content.Context;
import com.facebook.react.devsupport.DevInternalSettings;
import com.facebook.react.modules.debug.interfaces.DeveloperSettings;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: PerftestDevSupportManager.kt */
@Metadata(d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\b\u0010\f\u001a\u00020\rH\u0016J\b\u0010\u000e\u001a\u00020\rH\u0016R\u0014\u0010\u0006\u001a\u00020\u0007X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\b\u0010\tR\u000e\u0010\n\u001a\u00020\u000bX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000f"}, d2 = {"Lcom/facebook/react/devsupport/PerftestDevSupportManager;", "Lcom/facebook/react/devsupport/ReleaseDevSupportManager;", "applicationContext", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "devSettings", "Lcom/facebook/react/modules/debug/interfaces/DeveloperSettings;", "getDevSettings", "()Lcom/facebook/react/modules/debug/interfaces/DeveloperSettings;", "devServerHelper", "Lcom/facebook/react/devsupport/DevServerHelper;", "startInspector", "", "stopInspector", "ReactAndroid_release"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes.dex */
public final class PerftestDevSupportManager extends ReleaseDevSupportManager {
    private final DevServerHelper devServerHelper;
    private final DeveloperSettings devSettings;

    public PerftestDevSupportManager(Context applicationContext) {
        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
        this.devSettings = new DevInternalSettings(applicationContext, new DevInternalSettings.Listener() { // from class: com.facebook.react.devsupport.PerftestDevSupportManager$devSettings$1
            @Override // com.facebook.react.devsupport.DevInternalSettings.Listener
            public void onInternalSettingsChanged() {
            }
        });
        this.devServerHelper = new DevServerHelper(getDevSettings(), applicationContext, getDevSettings().getPackagerConnectionSettings());
    }

    @Override // com.facebook.react.devsupport.ReleaseDevSupportManager, com.facebook.react.devsupport.interfaces.DevSupportManager
    public DeveloperSettings getDevSettings() {
        return this.devSettings;
    }

    @Override // com.facebook.react.devsupport.ReleaseDevSupportManager, com.facebook.react.devsupport.interfaces.DevSupportManager
    public void startInspector() {
        this.devServerHelper.openInspectorConnection();
    }

    @Override // com.facebook.react.devsupport.ReleaseDevSupportManager, com.facebook.react.devsupport.interfaces.DevSupportManager
    public void stopInspector() {
        this.devServerHelper.closeInspectorConnection();
    }
}
