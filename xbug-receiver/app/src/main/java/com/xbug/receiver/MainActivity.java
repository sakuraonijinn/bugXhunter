package com.xbug.receiver;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends android.app.Activity {
    private static final String TAG = "XBugReceiver";
    private static final int PERMISSION_REQUEST_CODE = 100;

    private TextView statusText;
    private Button startButton;
    private Button stopButton;
    private AudioReceiverService service;
    private boolean bound = false;

    @Override
    protected void onCreate(android.os.Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.statusText);
        startButton = findViewById(R.id.startButton);
        stopButton = findViewById(R.id.stopButton);

        startButton.setOnClickListener(v -> startReceiver());
        stopButton.setOnClickListener(v -> stopReceiver());

        checkPermissions();
    }

    private void checkPermissions() {
        String[] perms = {
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.FOREGROUND_SERVICE
        };
        for (String p : perms) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, new String[]{p}, PERMISSION_REQUEST_CODE);
                break;
            }
        }
    }

    @Override
    protected void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults[0] != PackageManager.PERMISSION_GRANTED || grantResults[1] != PackageManager.PERMISSION_GRANTED) {
                runOnUiThread(() -> statusText.setText("Permission denied - Receiver stopped"));
            } else {
                bindToService();
            }
        }
    }

    private void bindToService() {
        serviceIntent = new Intent(this, AudioReceiverService.class);
        if (!service.isBound()) {
            bindService(serviceIntent, serviceConnection, ContextCompat.BIND_AUTO_CREATE);
        }
    }

    private Intent serviceIntent;
    private android.content.ServiceConnection serviceConnection;

    private void startReceiver() {
        Intent intent = new Intent(this, AudioReceiverService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        updateUI();
    }

    private void stopReceiver() {
        Intent intent = new Intent(this, AudioReceiverService.class);
        stopService(intent);
        updateUI();
    }

    private void updateUI() {
        statusText.setText("Status: STOPPED");
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
    }

    private ServiceConnection serviceConnection = new android.content.ServiceConnection() {
        @Override
        public void onServiceConnected(android.content.ComponentName name, IBinder binder) {
            bound = true;
            updateUI();
        }

        @Override
        public void onServiceDisconnected(android.content.ComponentName name) {
            bound = false;
            updateUI();
        }
    };
}
