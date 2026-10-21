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
    // ------------------------------------------------------------------
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            report('Debug.isDebuggerConnected()', 'true');
            return false;
        };
        Debug.waitingForDebugger.implementation = function () {
            report('Debug.waitingForDebugger()', 'true');
            return false;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // JNI: the native ptrace self-check is the most common one.
    // ------------------------------------------------------------------
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            report('Debug.isDebuggerConnected()', 'true');
            return false;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // /proc/self/status TracerPid, read straight from the file
    // ------------------------------------------------------------------
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        FileInputStream.read.overload('[B', 'int', 'int').implementation = function (buffer, offset, length) {
            var read = this.read(buffer, offset, length);
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
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // SystemClock.uptimeMillis, used for timing checks
    // ------------------------------------------------------------------
    try {
        var SystemClock = Java.use('android.os.SystemClock');
        SystemClock.uptimeMillis.implementation = function () {
            var now = this.uptimeMillis();
            report('SystemClock.uptimeMillis()', now);
            return now;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // ApplicationInfo.flags & FLAG_DEBUGGABLE
    // ------------------------------------------------------------------
    try {
        var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
        ApplicationInfo.flags.value = 0;
        console.log('[anti-debug] cleared ApplicationInfo.flags');
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // TracerPid native check, via the libc entry point most apps use.
    // ------------------------------------------------------------------
    try {
        var libc = Module.findExportByName('libc.so', 'ptrace');
        if (libc) {
            Interceptor.attach(libc, {
                onEnter: function (args) {
                    report('native ptrace()', 'request ' + args[0]);
                },
                onLeave: function (retval) {
                    // Return 0 so a ptrace(PTRACE_TRACEME) self-check
                    // looks like it succeeded.
                    retval.replace(0);
                }
            });
        }
    } catch (e) { /* not present */ }

    console.log('[anti-debug] hooks installed');
});
