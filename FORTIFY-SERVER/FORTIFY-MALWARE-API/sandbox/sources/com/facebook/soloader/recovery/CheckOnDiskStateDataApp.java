package com.facebook.soloader.recovery;

import android.content.Context;
import com.facebook.soloader.BackupSoSource;
import com.facebook.soloader.DirectorySoSource;
import com.facebook.soloader.LogUtil;
import com.facebook.soloader.SoLoader;
import com.facebook.soloader.SoLoaderULError;
import com.facebook.soloader.SoSource;
import com.facebook.soloader.UnpackingSoSource;
import java.io.File;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class CheckOnDiskStateDataApp implements RecoveryStrategy {
    private final Context mContext;

    public CheckOnDiskStateDataApp(Context context) {
        this.mContext = context;
    }

    @Override // com.facebook.soloader.recovery.RecoveryStrategy
    public boolean recover(UnsatisfiedLinkError unsatisfiedLinkError, SoSource[] soSourceArr) {
        if (!(unsatisfiedLinkError instanceof SoLoaderULError)) {
            return false;
        }
        LogUtil.e(SoLoader.TAG, "Checking /data/app missing libraries.");
        File file = new File(this.mContext.getApplicationInfo().nativeLibraryDir);
        if (!file.exists()) {
            LogUtil.e(SoLoader.TAG, "Native library directory " + file + " does not exist, exiting /data/app recovery.");
            return false;
        }
        ArrayList arrayList = new ArrayList();
        int length = soSourceArr.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                break;
            }
            SoSource soSource = soSourceArr[i];
            if (soSource instanceof BackupSoSource) {
                BackupSoSource backupSoSource = (BackupSoSource) soSource;
                try {
                    for (UnpackingSoSource.Dso dso : backupSoSource.getDsosBaseApk()) {
                        if (!new File(file, dso.name).exists()) {
                            arrayList.add(dso.name);
                        }
                    }
                    if (arrayList.isEmpty()) {
                        LogUtil.e(SoLoader.TAG, "No libraries missing from " + file);
                        return false;
                    }
                    LogUtil.e(SoLoader.TAG, "Missing libraries from " + file + ": " + arrayList.toString() + ", will run prepare on tbe backup so source");
                    backupSoSource.prepare(0);
                } catch (Exception e) {
                    LogUtil.e(SoLoader.TAG, "Encountered an exception while recovering from /data/app failure ", e);
                    return false;
                }
            } else {
                i++;
            }
        }
        for (SoSource soSource2 : soSourceArr) {
            if ((soSource2 instanceof DirectorySoSource) && !(soSource2 instanceof BackupSoSource)) {
                ((DirectorySoSource) soSource2).setExplicitDependencyResolution();
            }
        }
        LogUtil.e(SoLoader.TAG, "Successfully recovered from /data/app disk failure.");
        return true;
    }
}
