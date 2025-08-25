package com.facebook.common.file;

import java.io.File;

/* loaded from: classes.dex */
public class FileTree {
    public static void walkFileTree(File file, FileTreeVisitor fileTreeVisitor) {
        fileTreeVisitor.preVisitDirectory(file);
        File[] fileArrListFiles = file.listFiles();
        if (fileArrListFiles != null) {
            for (File file2 : fileArrListFiles) {
                if (file2.isDirectory()) {
                    walkFileTree(file2, fileTreeVisitor);
                } else {
                    fileTreeVisitor.visitFile(file2);
                }
            }
        }
        fileTreeVisitor.postVisitDirectory(file);
    }

    public static boolean deleteContents(File file) {
        File[] fileArrListFiles = file.listFiles();
        boolean zDeleteRecursively = true;
        if (fileArrListFiles != null) {
            for (File file2 : fileArrListFiles) {
                zDeleteRecursively &= deleteRecursively(file2);
            }
        }
        return zDeleteRecursively;
    }

    public static boolean deleteRecursively(File file) {
        if (file.isDirectory()) {
            deleteContents(file);
        }
        return file.delete();
    }
}
