package com.facebook.soloader;

import android.os.StrictMode;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class DirectorySoSource extends SoSource {
    public static final int ON_LD_LIBRARY_PATH = 2;
    public static final int RESOLVE_DEPENDENCIES = 1;
    protected final List<String> denyList;
    protected int flags;
    protected final File soDirectory;

    public DirectorySoSource(File file, int i) {
        this(file, i, new String[0]);
    }

    public void setExplicitDependencyResolution() {
        this.flags |= 1;
    }

    public DirectorySoSource(File file, int i, String[] strArr) {
        this.soDirectory = file;
        this.flags = i;
        this.denyList = Arrays.asList(strArr);
    }

    @Override // com.facebook.soloader.SoSource
    public int loadLibrary(String str, int i, StrictMode.ThreadPolicy threadPolicy) throws IOException {
        return loadLibraryFrom(str, i, this.soDirectory, threadPolicy);
    }

    protected int loadLibraryFrom(String str, int i, File file, StrictMode.ThreadPolicy threadPolicy) throws IOException {
        if (SoLoader.sSoFileLoader == null) {
            throw new IllegalStateException("SoLoader.init() not yet called");
        }
        if (this.denyList.contains(str)) {
            LogUtil.d(SoLoader.TAG, str + " is on the denyList, skip loading from " + file.getCanonicalPath());
            return 0;
        }
        File soFileByName = getSoFileByName(str);
        if (soFileByName == null) {
            LogUtil.v(SoLoader.TAG, str + " file not found on " + file.getCanonicalPath());
            return 0;
        }
        String canonicalPath = soFileByName.getCanonicalPath();
        LogUtil.d(SoLoader.TAG, str + " file found at " + canonicalPath);
        if ((i & 1) != 0 && (this.flags & 2) != 0) {
            LogUtil.d(SoLoader.TAG, str + " loaded implicitly");
            return 2;
        }
        if ((this.flags & 1) != 0) {
            ElfFileChannel elfFileChannel = new ElfFileChannel(soFileByName);
            try {
                NativeDeps.loadDependencies(str, elfFileChannel, i, threadPolicy);
                elfFileChannel.close();
            } catch (Throwable th) {
                try {
                    elfFileChannel.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
                throw th;
            }
        } else {
            LogUtil.d(SoLoader.TAG, "Not resolving dependencies for " + str);
        }
        try {
            SoLoader.sSoFileLoader.load(canonicalPath, i);
            return 1;
        } catch (UnsatisfiedLinkError e) {
            throw SoLoaderULErrorFactory.create(str, e);
        }
    }

    @Override // com.facebook.soloader.SoSource
    @Nullable
    public File getSoFileByName(String str) throws IOException {
        File file = new File(this.soDirectory, str);
        if (file.exists()) {
            return file;
        }
        return null;
    }

    @Override // com.facebook.soloader.SoSource
    @Nullable
    public String getLibraryPath(String str) throws IOException {
        File soFileByName = getSoFileByName(str);
        if (soFileByName == null) {
            return null;
        }
        return soFileByName.getCanonicalPath();
    }

    @Override // com.facebook.soloader.SoSource
    @Nullable
    public String[] getLibraryDependencies(String str) throws IOException {
        File soFileByName = getSoFileByName(str);
        if (soFileByName == null) {
            return null;
        }
        ElfFileChannel elfFileChannel = new ElfFileChannel(soFileByName);
        try {
            String[] dependencies = NativeDeps.getDependencies(str, elfFileChannel);
            elfFileChannel.close();
            return dependencies;
        } catch (Throwable th) {
            try {
                elfFileChannel.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    @Override // com.facebook.soloader.SoSource
    @Nullable
    public File unpackLibrary(String str) throws IOException {
        return getSoFileByName(str);
    }

    @Override // com.facebook.soloader.SoSource
    public void addToLdLibraryPath(Collection<String> collection) {
        try {
            collection.add(this.soDirectory.getCanonicalPath());
        } catch (IOException e) {
            LogUtil.e(SoLoader.TAG, "Failed to get canonical path for " + this.soDirectory.getName() + " due to " + e.toString() + ", falling to the absolute one");
            collection.add(this.soDirectory.getAbsolutePath());
        }
    }

    @Override // com.facebook.soloader.SoSource
    public String getName() {
        return "DirectorySoSource";
    }

    @Override // com.facebook.soloader.SoSource
    public String toString() {
        String name;
        try {
            name = String.valueOf(this.soDirectory.getCanonicalPath());
        } catch (IOException unused) {
            name = this.soDirectory.getName();
        }
        return getName() + "[root = " + name + " flags = " + this.flags + ']';
    }
}
