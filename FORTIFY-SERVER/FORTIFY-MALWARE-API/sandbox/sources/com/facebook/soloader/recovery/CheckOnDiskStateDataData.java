package com.facebook.soloader.recovery;

import com.facebook.soloader.BackupSoSource;
import com.facebook.soloader.LogUtil;
import com.facebook.soloader.SoLoader;
import com.facebook.soloader.SoLoaderULError;
import com.facebook.soloader.SoSource;
import com.facebook.soloader.UnpackingSoSource;

/* loaded from: classes.dex */
public class CheckOnDiskStateDataData implements RecoveryStrategy {
    @Override // com.facebook.soloader.recovery.RecoveryStrategy
    public boolean recover(UnsatisfiedLinkError unsatisfiedLinkError, SoSource[] soSourceArr) {
        if (!(unsatisfiedLinkError instanceof SoLoaderULError)) {
            return false;
        }
        LogUtil.e(SoLoader.TAG, "Checking /data/data missing libraries.");
        boolean z = false;
        for (SoSource soSource : soSourceArr) {
            if ((soSource instanceof UnpackingSoSource) && !(soSource instanceof BackupSoSource)) {
                UnpackingSoSource unpackingSoSource = (UnpackingSoSource) soSource;
                try {
                    UnpackingSoSource.Dso[] dsosBaseApk = unpackingSoSource.getDsosBaseApk();
                    int length = dsosBaseApk.length;
                    int i = 0;
                    while (true) {
                        if (i < length) {
                            UnpackingSoSource.Dso dso = dsosBaseApk[i];
                            if (unpackingSoSource.getSoFileByName(dso.name) == null) {
                                LogUtil.e(SoLoader.TAG, "Missing " + dso.name + " from " + unpackingSoSource.getName() + ", will force prepare.");
                                unpackingSoSource.prepare(2);
                                z = true;
                                break;
                            }
                            i++;
                        }
                    }
                } catch (Exception e) {
                    LogUtil.e(SoLoader.TAG, "Encountered an exception while recovering from /data/data failure ", e);
                    return false;
                }
            }
        }
        if (z) {
            LogUtil.e(SoLoader.TAG, "Successfully recovered from /data/data disk failure.");
            return true;
        }
        LogUtil.e(SoLoader.TAG, "No libraries missing from unpacking so paths while recovering /data/data failure");
        return false;
    }
}
