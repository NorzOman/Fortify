package com.facebook.soloader.recovery;

import com.facebook.soloader.SoSource;

/* loaded from: classes.dex */
public interface RecoveryStrategy {
    public static final int FLAG_ENABLE_DSONOTFOUND_ERROR_RECOVERY_FOR_BACKUP_SO_SOURCE = 1;

    boolean recover(UnsatisfiedLinkError unsatisfiedLinkError, SoSource[] soSourceArr);
}
