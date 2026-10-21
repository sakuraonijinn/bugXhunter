/*
 * shared_prefs_dump.js
 *
 * Purpose: read the app's SharedPreferences, which usually holds
 *          session tokens, flags and settings that tell you how the app
 *          behaves.
 *
 * Reports: every preference file in the app's shared_prefs directory,
 *          with its keys and values.
 *
 * Run:  frida -U -n com.example.app -l shared_prefs_dump.js
 */

'use strict';

Java.perform(function () {
    function dumpFile(path) {
        try {
            var FileInputStream = Java.use('java.io.FileInputStream');
            var fis = FileInputStream.$new(path);
            var BufferedReader = Java.use('java.io.BufferedReader');
            var InputStreamReader = Java.use('java.io.InputStreamReader');
            var reader = BufferedReader.$new(InputStreamReader.$new(fis));
            var line = reader.readLine();
            var out = '';
            while (line !== null) {
                out += line + '\n';
                line = reader.readLine();
            }
            reader.close();
            return out;
        } catch (e) {
            return '<unreadable: ' + e + '>';
        }
    }

    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var app = ActivityThread.currentApplication();
        var ctx = app.getApplicationContext();
        var filesDir = ctx.getFilesDir().getAbsolutePath();
        var prefsDir = filesDir + '/shared_prefs';

        console.log('[prefs] scanning ' + prefsDir);
        var dir = java.io.File.$new(prefsDir);
        var list = dir.list();
        if (list === null) {
            console.log('[prefs] no shared_prefs directory');
        } else {
            for (var i = 0; i < list.length; i++) {
                var name = String(list[i]);
                if (name.endsWith('.xml')) {
                    console.log('[prefs] === ' + name + ' ===');
                    console.log(dumpFile(prefsDir + '/' + name));
                }
            }
        }
    } catch (e) {
        console.log('[prefs] dump failed: ' + e);
    }

    // ------------------------------------------------------------------
    // Also watch writes, so you can see a token being set.
    // ------------------------------------------------------------------
    try {
        var Editor = Java.use('android.content.SharedPreferences$Editor');
        var putString = Editor.putString.overload('java.lang.String', 'java.lang.String');
        putString.implementation = function (key, value) {
            console.log('[prefs] putString ' + key + ' = ' + value);
            return putString.call(this, key, value);
        };
    } catch (e) { /* not present */ }

    console.log('[prefs] hooks installed');
});
