package com.xbug.receiver;

import android.Manifest;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "XBugReceiver";
    private static final int PERMISSION_REQUEST_CODE = 100;

    private TextView statusText;
    private Button startButton;
    private Button stopButton;
    private AudioReceiverService service = null;
    private boolean bound = false;
    private Intent serviceIntent;
    private ServiceConnection serviceConnection;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.statusText);
        startButton = findViewById(R.id.startButton);
        stopButton = findViewById(R.id.stopButton);

        startButton.setOnClickListener(v -> startReceiver());
        stopButton.setOnClickListener(v -> stopReceiver());

        serviceIntent = new Intent(this, AudioReceiverService.class);
        serviceConnection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder binder) {
                bound = true;
                updateUI(true);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                bound = false;
                updateUI(false);
            }
        };

        checkPermissions();
    }

    private void checkPermissions() {
        String[] perms = {
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.FOREGROUND_SERVICE,
            Manifest.permission.FOREGROUND_SERVICE_MICROPHONE
        };
        boolean allGranted = true;
        for (String p : perms) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }
        if (!allGranted) {
            ActivityCompat.requestPermissions(this, perms, PERMISSION_REQUEST_CODE);
        } else {
            bindToService();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            boolean allGranted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            if (allGranted) {
                bindToService();
            } else {
                runOnUiThread(() -> statusText.setText(getString(R.string.permission_denied)));
            }
        }
    }

    private void bindToService() {
        if (!bound) {
            bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE);
        }
    }

    @Override
    protected void onDestroy() {
        if (bound) {
            unbindService(serviceConnection);
            bound = false;
        }
        super.onDestroy();
    }

    private void startReceiver() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        updateUI(true);
    }

    private void stopReceiver() {
        stopService(serviceIntent);
        updateUI(false);
    }

    private void updateUI(boolean running) {
        runOnUiThread(() -> {
            if (running) {
                statusText.setText(getString(R.string.status_running));
                startButton.setEnabled(false);
                stopButton.setEnabled(true);
            } else {
                statusText.setText(getString(R.string.status_stopped));
                startButton.setEnabled(true);
                stopButton.setEnabled(false);
            }
        });
    }
}
