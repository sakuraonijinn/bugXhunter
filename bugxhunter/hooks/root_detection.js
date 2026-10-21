/*
 * root_detection.js
 *
 * Purpose: find out how the app decides it is running on a rooted
 *          device. Hooks the usual suspects and prints the stack trace
 *          for every one that trips, which is what tells you which
 *          check to patch.
 *
 * Reports: the file path, the return value and the calling stack for
 *          each root check that fires.
 *
 * Run:  frida -U -n com.example.app -l root_detection.js
 */

'use strict';

Java.perform(function () {
    var ROOT_PATHS = [
        '/system/bin/su', '/system/xbin/su', '/sbin/su', '/su',
        '/system/xbin/busybox', '/system/app/Superuser.apk',
        '/data/local/xposed/modules', '/data/local/tmp/frida-server',
    ];

    function trace(label) {
        var Throwable = Java.use('java.lang.Throwable');
        var stack = Throwable.$new().getStackTrace();
        var lines = [];
        for (var i = 0; i < stack.length && i < 12; i++) {
            lines.push('    at ' + stack[i].toString());
        }
        console.log('[root-detect] ' + label + '\n' + lines.join('\n'));
    }

    // ------------------------------------------------------------------
    // File.exists on the known root paths
    // ------------------------------------------------------------------
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function (path) {
            var result = this.exists();
            var p = String(path);
            for (var i = 0; i < ROOT_PATHS.length; i++) {
                if (p === ROOT_PATHS[i]) {
                    console.log('[root-detect] File.exists("' + p + '") -> ' + result);
                    trace('File.exists(' + p + ')');
                }
            }
            return result;
        };
    } catch (e) {
        console.log('[root-detect] could not hook java.io.File: ' + e);
    }

    // ------------------------------------------------------------------
    // Runtime.exec, often used to run "which su" or "su -c id"
    // ------------------------------------------------------------------
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd && /su|busybox|which\s+su|magisk|supersu/i.test(String(cmd))) {
                console.log('[root-detect] Runtime.exec: ' + cmd);
                trace('Runtime.exec(' + cmd + ')');
            }
            return this.exec(cmd);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // SystemProperties.get, used to read ro.debuggable and friends
    // ------------------------------------------------------------------
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            var value = this.get(key);
            if (/debuggable|secure|build\.type|ro\./i.test(String(key))) {
                console.log('[root-detect] SystemProperties.get("' + key + '") = ' + value);
            }
            return value;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // PackageManager.getInstallerPackageName, often null for a sideloaded
    // build, which some apps treat as a root signal.
    // ------------------------------------------------------------------
    try {
        var PackageManager = Java.use('android.content.pm.PackageManager');
        PackageManager.getInstallerPackageName.overload('java.lang.String')
            .implementation = function (pkg) {
                var value = this.getInstallerPackageName(pkg);
                console.log('[root-detect] getInstallerPackageName("' + pkg + '") = ' + value);
                return value;
            };
    } catch (e) { /* not present */ }

    console.log('[root-detect] hooks installed');
});
