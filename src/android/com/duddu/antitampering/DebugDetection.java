package com.duddu.antitampering;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;

import java.lang.reflect.Field;
import java.util.List;
import java.io.File;

class DebugDetection {
    public static void check(String packageName, Context context) throws Exception {
        if (isDebuggerPresent(packageName, context)) {
            throw new Exception("Debugger is present");
        }
        if (hasDebuggerAttached()) {
            throw new Exception("Debugger attached");
        }
        if (isFridaPresent(context) || isFridaLibraryPresent() || isFridaRelatedFilesPresent()) {
            throw new Exception("Frida is present");
        }
    }

    private static Boolean hasDebuggerAttached() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    private static boolean isDebuggerPresent(String packageName, Context context) {
        try {
            if ((context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0).applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                //Debug and development mode
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return true;
        }
    }

    private static boolean isFridaLibraryPresent() {
        try {
            System.loadLibrary("frida-gadget");
            return true;
        } catch (UnsatisfiedLinkError e) {
            return false;
        }
    }

    private static boolean isFridaRelatedFilesPresent() {
        String[] fridaRelatedPaths = {
                "/data/local/tmp/frida-server",
                "/data/local/tmp/frida",
                "/system/bin/frida-server",
                "/system/bin/frida",
                "/data/data/com.termux/files/home/.frida-server",
                "/data/data/com.termux/files/home/.frida",
        };
        for (String path : fridaRelatedPaths) {
            File file = new File(path);
            if (file.exists()) {
                return true;
            }
        }
        return false;
    }

    private static boolean isFridaPresent(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> runningProcesses = activityManager.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo processInfo : runningProcesses) {
            if (processInfo.processName.equals("frida-server")) {
                return true;
            }
        }
        return false;
    }
}