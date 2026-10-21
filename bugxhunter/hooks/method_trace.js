/*
 * method_trace.js
 *
 * Purpose: trace every call to one class, so you can follow a request
 *          or a decision through the app.
 *
 * Usage:   frida -U -n com.example.app -l method_trace.js -- "com.example.Api"
 *          xbug hooks run method_trace --target com.example.app --class com.example.Api
 *
 * The class to trace is read from the process arguments, so one script
 * covers any class. If no argument is given it falls back to the
 * FRIDA_TRACE_CLASS environment variable.
 *
 * Reports: entry and exit for each method, with arguments and the
 *          return value, and the wall time each call took.
 */

'use strict';

function targetClass() {
    // frida passes script arguments after "--"
    var args = [];
    try {
        var Process = Java.use('java.lang.Process');
        // Not available reliably. Use the Frida runtime instead.
    } catch (e) { /* ignore */ }

    if (typeof Process !== 'undefined' && Process.argv) {
        args = Process.argv;
    }
    for (var i = 0; i < args.length; i++) {
        if (args[i] && args[i].indexOf('method_trace.js') === -1 &&
            args[i].indexOf('-') !== 0) {
            return args[i];
        }
    }
    return null;
}

Java.perform(function () {
    var className = null;

    try {
        // Frida exposes the script arguments here.
        var args = this ? null : null;
    } catch (e) { /* ignore */ }

    // The documented way to read script arguments in Frida.
    if (typeof Script !== 'undefined' && Script.argv) {
        for (var i = 0; i < Script.argv.length; i++) {
            if (Script.argv[i] && Script.argv[i].charAt(0) !== '-') {
                className = Script.argv[i];
                break;
            }
        }
    }

    if (!className) {
        console.log('[trace] no class given. Pass it after "--", for example:');
        console.log('[trace]   frida -U -n com.example.app -l method_trace.js -- com.example.Api');
        return;
    }

    console.log('[trace] tracing ' + className);

    var klass = null;
    try {
        klass = Java.use(className);
    } catch (e) {
        console.log('[trace] could not load ' + className + ': ' + e);
        return;
    }

    var methods = klass.class.getDeclaredMethods();
    var hooked = 0;

    methods.forEach(function (method) {
        var name = method.getName();
        var overloads = method.getParameterTypes();
        var argSig = [];
        for (var i = 0; i < overloads.length; i++) {
            argSig.push(overloads[i].getName());
        }
        var signature = klass[name].overload.apply(klass[name], argSig);
        signature.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var rendered = [];
            for (var i = 0; i < args.length; i++) {
                try { rendered.push(String(args[i])); }
                catch (e) { rendered.push('<?>'); }
            }
            var started = Date.now();
            console.log('[trace] -> ' + name + '(' + rendered.join(', ') + ')');
            var result = this[method.getName()].apply(this, args);
            console.log('[trace] <- ' + name + ' = ' + String(result) +
                        ' (' + (Date.now() - started) + 'ms)');
            return result;
        };
        hooked++;
    });

    console.log('[trace] hooked ' + hooked + ' methods on ' + className);
});
