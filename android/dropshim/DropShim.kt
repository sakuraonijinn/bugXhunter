// DropShim.kt
// Android-native driver shim implementing the CoilDriver and Magnetometer
// interfaces from bugxhunter/drop/driver.py, so the Python protocol stack
// can run on real phone hardware with no extra equipment.
//
// Wiring:
//   - CoilDriver  -> Vibrator service (vibration motor = magnetic pulser)
//   - Magnetometer -> SensorManager TYPE_MAGNETIC_FIELD
//
// The shim exposes a simple localhost socket (port 8765) that the Python
// side talks to with JSON lines, so bugxhunter.drop can drive real HW.

package com.bugxhunter.dropshim

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

class DropShim(private val context: Context) {

    // ---- CoilDriver (vibrator motor) ----
    private val vibrator: Vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager).defaultVibrator
    } else {
        @Suppress("DEPRECATION")
        context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
    }

    fun pulse(durationMs: Long) {
        if (durationMs <= 0) return
        vibrator.vibrate(VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE))
        Thread.sleep(durationMs) // block so symbol timing stays synchronous
    }

    fun idle() {
        vibrator.cancel()
    }

    // ---- Magnetometer ----
    private val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private val magSensor = sensorManager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)

    @Volatile private var latest: Float = 0f
    private val listener = object : SensorEventListener {
        override fun onSensorChanged(e: SensorEvent) {
            val x = e.values[0]; val y = e.values[1]; val z = e.values[2]
            latest = kotlin.math.sqrt(x*x + y*y + z*z)
        }
        override fun onAccuracyChanged(s: Sensor, a: Int) {}
    }

    fun startSensing() {
        sensorManager.registerListener(listener, magSensor, SensorManager.SENSOR_DELAY_FASTEST)
    }

    fun sample(): Float = latest

    fun stopSensing() {
        sensorManager.unregisterListener(listener)
    }

    // ---- Socket bridge to Python ----
    // Protocol (JSON lines):
    //   {"cmd":"pulse","ms":3.0}   -> {"ok":true}
    //   {"cmd":"idle"}              -> {"ok":true}
    //   {"cmd":"sample"}            -> {"value":12.34}
    //   {"cmd":"start"}             -> {"ok":true}
    //   {"cmd":"stop"}              -> {"ok":true}
    fun serve(port: Int = 8765) {
        startSensing()
        thread(isDaemon = true) {
            val server = ServerSocket(port)
            while (true) {
                val client: Socket = server.accept()
                thread {
                    val reader = BufferedReader(InputStreamReader(client.getInputStream()))
                    val writer = PrintWriter(client.getOutputStream(), true)
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        val resp = handle(line!!)
                        writer.println(resp)
                    }
                    client.close()
                }
            }
        }
    }

    private fun handle(line: String): String {
        return try {
            val cmd = line.substringAfter("\"cmd\":\"").substringBefore("\"")
            when (cmd) {
                "pulse" -> {
                    val ms = line.substringAfter("\"ms\":").substringBefore("}").trim().toDouble()
                    pulse(ms.toLong().coerceAtLeast(1))
                    """{"ok":true}"""
                }
                "idle" -> { idle(); """{"ok":true}""" }
                "sample" -> """{"value":$latest}"""
                "start" -> { startSensing(); """{"ok":true}""" }
                "stop" -> { stopSensing(); """{"ok":true}""" }
                else -> """{"error":"unknown cmd"}"""
            }
        } catch (e: Exception) {
            """{"error":"${e.message}"}"""
        }
    }
}

