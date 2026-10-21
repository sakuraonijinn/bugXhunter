/*
 * method_trace.js
 *
 * Purpose: trace every call to one class, so you can follow a request
 *          or a decision through the app.
 *
 * Usage:   frida -U -n com.example.app -l method_trace.js -- com.example.Api
 *          xbug hooks run method_trace --target com.example.app --class com.example.Api
 *
 * The class to trace is read from the script arguments, so one script
 * covers any class. The correct argument spelling for a given build is
 * whatever `xbug hooks discover` reports.
 *
 * Reports: entry and exit for each method, with arguments and the
 *          return value, and the wall time each call took.
 */

'use strict';

Java.perform(function () {
    // Script arguments arrive after "--". Frida exposes them here.
    var args = (typeof Script !== 'undefined' && Script.argv) ? Script.argv : [];
    var className = null;
    for (var i = 0; i < args.length; i++) {
        if (args[i] && args[i].charAt(0) !== '-') {
            className = args[i];
            break;
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

    // Walk the class and its superclasses, and hook every declared
    // method. The overload object is saved so the original can be
    // called without recursing back into the replacement.
    var hooked = 0;
    var skipped = 0;

    function hookClass(cls) {
        var methods = null;
        try {
            methods = cls.class.getDeclaredMethods();
        } catch (e) {
            return;
        }
        if (!methods) { return; }

        methods.forEach(function (method) {
            var name = method.getName();
            var paramTypes = method.getParameterTypes();
            var argSig = [];
            for (var i = 0; i < paramTypes.length; i++) {
                argSig.push(paramTypes[i].getName());
            }

            var overload = null;
            try {
                overload = cls[name].overload.apply(cls[name], argSig);
            } catch (e) {
                skipped++;
                return;
            }

            overload.implementation = function () {
                var callArgs = Array.prototype.slice.call(arguments);
                var rendered = [];
                for (var i = 0; i < callArgs.length; i++) {
                    try { rendered.push(String(callArgs[i])); }
                    catch (e) { rendered.push('<?>'); }
                }
                var started = Date.now();
                console.log('[trace] -> ' + name + '(' + rendered.join(', ') + ')');
                var result = overload.call(this, ...callArgs);
                console.log('[trace] <- ' + name + ' = ' + String(result) +
                            ' (' + (Date.now() - started) + 'ms)');
                return result;
            };
            hooked++;
        });
    }

    hookClass(klass);

    var superClass = null;
    try {
        superClass = klass.class.getSuperclass();
    } catch (e) { /* ignore */ }
    while (superClass !== null) {
        try {
            var superWrapper = Java.use(superClass.getName());
            hookClass(superWrapper);
        } catch (e) { /* ignore */ }
        try {
            superClass = superClass.getSuperclass();
        } catch (e) { break; }
    }

    console.log('[trace] hooked ' + hooked + ' methods on ' + className +
                (skipped ? ', skipped ' + skipped : ''));
});
