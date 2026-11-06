package com.xbug.receiver;

public class XBugApplication extends android.app.Application {
    @Override
    public void onCreate() {
        super.onCreate();
        try {
            System.loadLibrary("audio_receiver");
        } catch (UnsatisfiedLinkError e) {
            android.util.Log.e("XBugApplication", "Failed to preload native library: " + e.getMessage());
        }
    }
}
