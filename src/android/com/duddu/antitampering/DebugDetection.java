package com.duddu.antitampering;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;

import java.lang.reflect.Field;


class DebugDetection {

    public static void check(String packageName, Context context) throws Exception {
        if (isDebuggerPresent(packageName, context)) {
            throw new Exception("Debugger is present");
        }
        if (hasDebuggerAttached()) {
            throw new Exception("Debugger attached");
        }
        if (getDebugField(packageName)) {
            throw new Exception("App running in Debug mode");
        }
    }

    private static Boolean getDebugField(String packageName) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        Class<?> buildConfigClass = Class.forName(packageName.concat(".BuildConfig"));
        Field debugField = buildConfigClass.getField("DEBUG");
        return debugField.getBoolean(null);
    }

    private static Boolean hasDebuggerAttached() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    private static boolean isDebuggerPresent(String packageName, Context context) {
        try {
            if ((context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0).applicationInfo.flags &
                    ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                //Debug and development mode
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return true;
        }
    }
}
