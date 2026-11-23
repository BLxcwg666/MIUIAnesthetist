package com.xposed.miuianesthetist;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.os.Parcel;

import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static com.xposed.miuianesthetist.XposedHelpersWraper.findAndHookConstructor;
import static com.xposed.miuianesthetist.XposedHelpersWraper.findAndHookMethod;
import static com.xposed.miuianesthetist.XposedHelpersWraper.log;
import static com.xposed.miuianesthetist.XposedHelpersWraper.setBooleanField;

public class DisableSecurityCheck extends BaseXposedHookLoadPackage {
    private static final String PMS_IMPL = "com.android.server.pm.PackageManagerServiceImpl";

    @Override
    public void initZygote(StartupParam startupParam) {
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!"android".equals(lpparam.packageName)) return;
        try {
            handleAndroid(lpparam);
        } catch (Throwable t) {
            log(t);
        }
    }

    // Hook points verified against HyperOS 2 (Android 15) miui-services.jar / services.jar
    private void handleAndroid(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader classLoader = lpparam.classLoader;

        //Remove the limit for disabling system apps (MIUI_CORE_APPS, shell disable-user, etc.)
        findAndHookMethod(PMS_IMPL, classLoader, "shouldRestrictEnabledSettingsChange",
                String.class, int.class, int.class, XC_MethodReplacement.DO_NOTHING);

        //Remove the limit for installing WebViewGoogle manually on MIUI China ROM.
        //Only skip the check for WebView: the same method also guards the signatures of
        //protected preinstalled apps, which should stay intact.
        findAndHookMethod(PMS_IMPL, classLoader, "verifyPackageForRelease",
                Context.class, String.class, "android.content.pm.SigningDetails",
                String.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if ("com.google.android.webview".equals(param.args[1])) {
                            param.setResult(null);
                        }
                    }
                });

        //Stop market:// intents from being hijacked to Xiaomi Market.
        //The last argument is the activity AOSP has already chosen, which the original method
        //returns as-is when it does not interfere.
        findAndHookMethod(PMS_IMPL, classLoader, "hookChooseBestActivity",
                Intent.class, String.class, long.class, List.class, int.class, ResolveInfo.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Intent intent = (Intent) param.args[0];
                        if (intent != null && "market".equals(intent.getScheme()) &&
                                Intent.ACTION_VIEW.equals(intent.getAction())) {
                            param.setResult(param.args[5]);
                        }
                    }
                });

        //Prevent some ultra sticky system apps (MiuiDaemon, FindDevice, etc.) from running
        //after have been disabled. AOSP keeps disabled persistent apps in this list and
        //ActivityManagerService starts them at boot.
        findAndHookMethod("com.android.server.pm.ComputerEngine", classLoader,
                "getPersistentApplications", boolean.class, int.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        @SuppressWarnings("unchecked")
                        List<ApplicationInfo> apps = (List<ApplicationInfo>) param.getResult();
                        if (apps == null) return;
                        List<ApplicationInfo> filtered = new ArrayList<>(apps.size());
                        for (ApplicationInfo info : apps) {
                            if (info.enabled && !"com.miui.greenguard".equals(info.packageName)) {
                                filtered.add(info);
                            } else {
                                log("PersistApps", "persist app : " + info.packageName +
                                        " should not add to start");
                            }
                        }
                        if (filtered.size() != apps.size()) {
                            param.setResult(filtered);
                        }
                    }
                });

        //Allow users disable system apps' notification channel in framework.jar
        XC_MethodHook blockable = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                setBooleanField(param.thisObject, "mBlockableSystem", true);
            }
        };
        findAndHookConstructor("android.app.NotificationChannel", classLoader, Parcel.class, blockable);
        findAndHookConstructor("android.app.NotificationChannel", classLoader,
                String.class, CharSequence.class, int.class, blockable);
    }
}
