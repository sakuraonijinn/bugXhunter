package com.xbug.receiver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

public class AudioReceiverService extends Service {
    private static final String TAG = "AudioReceiver";
    private boolean running = false;

    static {
        try {
            System.loadLibrary("audio_receiver");
            Log.i(TAG, "Native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library: " + e);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Service created");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        running = true;
        startForeground(1, buildNotification());
        initNativeAudioReceiver();
        return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION;
    }

    @Override
    public void onDestroy() {
        running = false;
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return new LocalBinder();
    }

    public boolean isRunning() {
        return running;
    }

    public class LocalBinder extends android.os.Binder {
        public AudioReceiverService getService() {
            return AudioReceiverService.this;
        }
    }

    private Notification buildNotification() {
        return NotificationCompat.Builder(this, "xbug_channel")
            .setContentTitle("XBug Receiver")
            .setContentText("Listening for audio drop...")
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setOngoing(true)
            .build();
    }

    // Load Channel for Android O+ if needed
    private void ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                "xbug_channel", "XBug Receiver", NotificationManager.IMPORTANCE_LOW);
            getSystemService(NotificationManager.class).createNotificationChannel(channel);
        }
    }

    private native void initNativeAudioReceiver();
}
