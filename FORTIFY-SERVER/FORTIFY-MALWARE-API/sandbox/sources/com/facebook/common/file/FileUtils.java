package com.facebook.common.file;

import com.facebook.common.internal.Preconditions;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import javax.annotation.Nullable;

/* loaded from: classes.dex */
public class FileUtils {
    public static void mkdirs(File file) throws CreateDirectoryException {
        if (file.exists()) {
            if (file.isDirectory()) {
                return;
            }
            if (!file.delete()) {
                throw new CreateDirectoryException(file.getAbsolutePath(), new FileDeleteException(file.getAbsolutePath()));
            }
        }
        if (!file.mkdirs() && !file.isDirectory()) {
            throw new CreateDirectoryException(file.getAbsolutePath());
        }
    }

    public static void rename(File file, File file2) throws RenameException {
        Throwable fileDeleteException;
        Preconditions.checkNotNull(file);
        Preconditions.checkNotNull(file2);
        file2.delete();
        if (file.renameTo(file2)) {
            return;
        }
        if (file2.exists()) {
            fileDeleteException = new FileDeleteException(file2.getAbsolutePath());
        } else if (!file.getParentFile().exists()) {
            fileDeleteException = new ParentDirNotFoundException(file.getAbsolutePath());
        } else {
            fileDeleteException = !file.exists() ? new FileNotFoundException(file.getAbsolutePath()) : null;
        }
        throw new RenameException("Unknown error renaming " + file.getAbsolutePath() + " to " + file2.getAbsolutePath(), fileDeleteException);
    }

    public static class CreateDirectoryException extends IOException {
        public CreateDirectoryException(String str) {
            super(str);
        }

        public CreateDirectoryException(String str, Throwable th) {
            super(str);
            initCause(th);
        }
    }

    public static class ParentDirNotFoundException extends FileNotFoundException {
        public ParentDirNotFoundException(String str) {
            super(str);
        }
    }

    public static class FileDeleteException extends IOException {
        public FileDeleteException(String str) {
            super(str);
        }
    }

    public static class RenameException extends IOException {
        public RenameException(String str) {
            super(str);
        }

        public RenameException(String str, @Nullable Throwable th) {
            super(str);
            initCause(th);
        }
    }
}
