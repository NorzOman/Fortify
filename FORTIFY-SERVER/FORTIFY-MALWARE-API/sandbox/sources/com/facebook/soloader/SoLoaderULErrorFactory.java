package com.facebook.soloader;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public class SoLoaderULErrorFactory {
    public static SoLoaderULError create(String str, UnsatisfiedLinkError unsatisfiedLinkError) {
        SoLoaderULError soLoaderULError;
        if (unsatisfiedLinkError.getMessage() != null && unsatisfiedLinkError.getMessage().contains("ELF")) {
            LogUtil.d(SoLoader.TAG, "Corrupted lib file detected");
            soLoaderULError = new SoLoaderCorruptedLibFileError(str, unsatisfiedLinkError.toString());
        } else if (corruptedLibName(str)) {
            LogUtil.d(SoLoader.TAG, "Corrupted lib name detected");
            soLoaderULError = new SoLoaderCorruptedLibNameError(str, "corrupted lib name: " + unsatisfiedLinkError.toString());
        } else {
            soLoaderULError = new SoLoaderULError(str, unsatisfiedLinkError.toString());
        }
        soLoaderULError.initCause(unsatisfiedLinkError);
        return soLoaderULError;
    }

    private static boolean corruptedLibName(String str) {
        Matcher matcher = Pattern.compile("\\P{ASCII}+").matcher(str);
        if (!matcher.find()) {
            return false;
        }
        LogUtil.w(SoLoader.TAG, "Library name is corrupted, contains non-ASCII characters " + matcher.group());
        return true;
    }
}
