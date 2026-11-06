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
import androidx.lifecycle.LifecycleService;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class AudioReceiverService extends LifecycleService {
    private static final String TAG = "AudioReceiver";
    private static final String BINARY_NAME = "audio_receiver";
    private boolean running = false;
    private Process receiverProcess = null;

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
        startReceiver();
        Log.i(TAG, "Service started");
        return ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
    }

    @Override
    public void onDestroy() {
        running = false;
        stopReceiver();
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

    private void startReceiver() {
        try {
            // Extract binary from assets if not already extracted
            File binaryFile = new File(getFilesDir(), BINARY_NAME);
            if (!binaryFile.exists()) {
                extractBinaryFromAssets(binaryFile);
            }

            // Make executable
            binaryFile.setExecutable(true);

            // Start the receiver process
            ProcessBuilder pb = new ProcessBuilder(binaryFile.getAbsolutePath());
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);
            receiverProcess = pb.start();

            // Read output in background thread
            new Thread(() -> {
                try (java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(receiverProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        Log.i(TAG, "Receiver: " + line);
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error reading receiver output: " + e.getMessage());
                }
            }).start();

            Log.i(TAG, "Receiver started: " + binaryFile.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "Failed to start receiver: " + e.getMessage());
        }
    }

    private void stopReceiver() {
        if (receiverProcess != null) {
            receiverProcess.destroy();
            receiverProcess = null;
        }
    }

    private void extractBinaryFromAssets(File outFile) {
        try (InputStream is = getAssets().open(BINARY_NAME);
             FileOutputStream fos = new FileOutputStream(outFile)) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = is.read(buffer)) != -1) {
                fos.write(buffer, 0, read);
            }
            Log.i(TAG, "Extracted binary to: " + outFile.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "Failed to extract binary: " + e.getMessage());
        }
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
}
