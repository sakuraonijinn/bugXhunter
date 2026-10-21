/*
 * anti_debug_bypass.js
 *
 * Purpose: stop the app noticing that it is being instrumented. Hooks
 *          the debugger checks and the timing checks that look for a
 *          tracer.
 *
 * Reports: every check that fires, with the value it was about to
 *          return, so you can see what it would have concluded.
 *
 * Run:  frida -U -n com.example.app -l anti_debug_bypass.js
 */

'use strict';

Java.perform(function () {
    function report(what, value) {
        console.log('[anti-debug] ' + what + ' -> ' + value);
    }

    // ------------------------------------------------------------------
    // android.os.Debug
    //
    // isDebuggerConnected() and waitingForDebugger() are the two the
    // app checks most often. Hook each exactly once, and reach the
    // original through the saved overload so the replacement cannot
    // call itself.
    // ------------------------------------------------------------------
    try {
        var Debug = Java.use('android.os.Debug');
        var isConnected = Debug.isDebuggerConnected.overload();
        isConnected.implementation = function () {
            report('Debug.isDebuggerConnected()', 'true');
            return false;
        };
        var waiting = Debug.waitingForDebugger.overload();
        waiting.implementation = function () {
            report('Debug.waitingForDebugger()', 'true');
            return false;
        };
    } catch (e) {
        console.log('[anti-debug] could not hook android.os.Debug: ' + e);
    }

    // ------------------------------------------------------------------
    // ApplicationInfo.flags and FLAG_DEBUGGABLE
    //
    // The flag is an instance field, so it has to be cleared on the
    // object the app is handed, not on the class. Hooking
    // PackageManager.getApplicationInfo is the way to get at it.
    // ------------------------------------------------------------------
    try {
        var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
        var FLAG_DEBUGGABLE = 0x2;
        var getAppInfo = ApplicationInfo.$new.overload(
            'java.lang.String', 'int', 'android.content.pm.ApplicationInfo');
        getAppInfo.implementation = function (pkg, flags, appInfo) {
            var result = getAppInfo.call(this, pkg, flags, appInfo);
            try {
                if (result !== null && result.flags !== undefined) {
                    if ((result.flags & FLAG_DEBUGGABLE) !== 0) {
                        report('ApplicationInfo.flags FLAG_DEBUGGABLE', 'cleared');
                        result.flags.value = result.flags.value & ~FLAG_DEBUGGABLE;
                    }
                }
            } catch (e) {
                console.log('[anti-debug] could not clear FLAG_DEBUGGABLE: ' + e);
            }
            return result;
        };
    } catch (e) {
        console.log('[anti-debug] could not hook ApplicationInfo: ' + e);
    }

    // ------------------------------------------------------------------
    // /proc/self/status TracerPid, read straight from the file
    // ------------------------------------------------------------------
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        var read3 = FileInputStream.read.overload('[B', 'int', 'int');
        read3.implementation = function (buffer, offset, length) {
            var read = read3.call(this, buffer, offset, length);
            try {
                if (read > 0) {
                    var text = Java.use('java.lang.String').$new(buffer, offset, read);
                    if (String(text).indexOf('TracerPid:') !== -1) {
                        report('TracerPid read', String(text).trim());
                    }
                }
            } catch (e) { /* keep going */ }
            return read;
        };
    } catch (e) {
        console.log('[anti-debug] could not hook FileInputStream.read: ' + e);
    }

    // ------------------------------------------------------------------
    // SystemClock.uptimeMillis, used for timing checks
    // ------------------------------------------------------------------
    try {
        var SystemClock = Java.use('android.os.SystemClock');
        var uptime = SystemClock.uptimeMillis.overload();
        uptime.implementation = function () {
            var now = uptime.call(this);
            report('SystemClock.uptimeMillis()', now);
            return now;
        };
    } catch (e) {
        console.log('[anti-debug] could not hook SystemClock: ' + e);
    }

    // ------------------------------------------------------------------
    // Native ptrace self-check. The app calls ptrace(PTRACE_TRACEME) and
    // treats a failure as "someone is tracing me", so returning success
    // is what defeats it.
    // ------------------------------------------------------------------
    try {
        var libc = Module.findExportByName('libc.so', 'ptrace');
        if (libc) {
            Interceptor.attach(libc, {
                onEnter: function (args) {
                    report('native ptrace()', 'request ' + args[0]);
                },
                onLeave: function (retval) {
                    retval.replace(0);
                }
            });
        }
    } catch (e) {
        console.log('[anti-debug] could not hook ptrace: ' + e);
    }

    console.log('[anti-debug] hooks installed');
});
