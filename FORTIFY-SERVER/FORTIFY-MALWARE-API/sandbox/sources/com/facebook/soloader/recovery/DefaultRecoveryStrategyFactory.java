package com.facebook.soloader.recovery;

import android.content.Context;

/* loaded from: classes.dex */
public class DefaultRecoveryStrategyFactory implements RecoveryStrategyFactory {
    private final BaseApkPathHistory mBaseApkPathHistory;
    private final Context mContext;
    private final int mRecoveryFlags;

    public DefaultRecoveryStrategyFactory(Context context, int i) {
        this.mContext = context;
        this.mRecoveryFlags = i;
        BaseApkPathHistory baseApkPathHistory = new BaseApkPathHistory(5);
        this.mBaseApkPathHistory = baseApkPathHistory;
        baseApkPathHistory.recordPathIfNew(context.getApplicationInfo().sourceDir);
    }

    @Override // com.facebook.soloader.recovery.RecoveryStrategyFactory
    public RecoveryStrategy get() {
        return new CompositeRecoveryStrategy(new DetectDataAppMove(this.mContext, this.mBaseApkPathHistory), new CheckBaseApkExists(this.mContext, this.mBaseApkPathHistory), new WaitForAsyncInit(), new CheckOnDiskStateDataApp(this.mContext), new ReunpackBackupSoSources(this.mRecoveryFlags), new CheckOnDiskStateDataData(), new ReunpackNonBackupSoSources(), new WaitForAsyncInit());
    }
}
