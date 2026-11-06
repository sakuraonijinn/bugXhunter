package com.xbug.receiver;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.lifecycle.LifecycleService;

public class AudioReceiverService extends LifecycleService {
    private static final String TAG = "AudioReceiver";
    private boolean running = false;

    static {
        try {
            System.loadLibrary("audio_receiver");
            Log.i(TAG, "Native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library: " + e.getMessage());
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        ensureNotificationChannel();
        Log.i(TAG, "Service created");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        running = true;
        startForeground(1, buildNotification());
        initNativeAudioReceiver();
        Log.i(TAG, "Service started");
        return ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
    }

    @Override
    public void onDestroy() {
        running = false;
        super.onDestroy();
        Log.i(TAG, "Service destroyed");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    public boolean isRunning() {
        return running;
    }

    private Notification buildNotification() {
        ensureNotificationChannel();
        return NotificationCompat.Builder(this, "xbug_channel")
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.status_listening))
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setOngoing(true)
            .build();
    }

    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            android.app.NotificationManager nm =
                (android.app.NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) {
                NotificationChannel channel = new NotificationChannel(
                    "xbug_channel",
                    getString(R.string.channel_name),
                    android.app.NotificationManager.IMPORTANCE_LOW);
                nm.createNotificationChannel(channel);
            }
        }
    }

    private native void initNativeAudioReceiver();
}
