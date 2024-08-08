package com.duddu.antitampering;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Handler;
import android.os.Looper;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;


public class AntiTamperingPlugin extends CordovaPlugin {

    private Activity activity;

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        activity = cordova.getActivity();
        checkAndStopExecution();
        super.initialize(cordova, webView);
    }

    private void checkAndStopExecution() {
        try {
            AssetsIntegrity.check(activity.getAssets());
            DebugDetection.check(activity.getPackageName(), activity.getApplicationContext());
        } catch (final Exception e) {
            showErrorDialog();
        }
    }

    private void showErrorDialog() {
        new Handler(Looper.getMainLooper()).post(() -> {
            new AlertDialog.Builder(activity)
                    .setTitle("Alerta de segurança")
                    .setMessage("Adulteração detectada e agora o aplicativo será encerrado")
                    .setCancelable(false)
                    .setPositiveButton("OK", (dialog, which) -> {
                        dialog.dismiss();
                        activity.finish();
                    })
                    .show();
        });
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            activity.finish();
        }, 3000);
    }



    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {

        if ("verify".equals(action)) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run () {
                    PluginResult result;
                    try {
                        DebugDetection.check(activity.getPackageName(), activity.getApplicationContext());
                        JSONObject response = new JSONObject();
                        response.put("assets", AssetsIntegrity.check(activity.getAssets()));
                        result = new PluginResult(PluginResult.Status.OK, response);
                    } catch (Exception e) {
                        showErrorDialog();
                        result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                    }
                    callbackContext.sendPluginResult(result);
                }
            });
            return true;
        }

        return false;

    }

}
