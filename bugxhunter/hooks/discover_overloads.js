/*
 * discover_overloads.js
 *
 * Purpose: list the real signatures of a class's methods, so you can
 *          write a hook against the build you actually have instead of
 *          guessing.
 *
 *          This is the first thing to run when a hook says "no such
 *          overload": the reason is almost always a version difference,
 *          and this prints the version's actual signatures.
 *
 * Usage:   frida -U -n com.example.app -l discover_overloads.js -- com.example.Api
 *          xbug hooks run discover_overloads --target com.example.app --class com.example.Api
 *
 * Reports: one line per method, with its full parameter signature and
 *          return type.
 */

'use strict';

Java.perform(function () {
    var args = (typeof Script !== 'undefined' && Script.argv) ? Script.argv : [];
    var className = null;
    for (var i = 0; i < args.length; i++) {
        if (args[i] && args[i].charAt(0) !== '-') {
            className = args[i];
            break;
        }
    }

    if (!className) {
        console.log('[discover] no class given. Pass it after "--", for example:');
        console.log('[discover]   frida -U -n com.example.app -l discover_overloads.js -- com.example.Api');
        return;
    }

    var klass = null;
    try {
        klass = Java.use(className);
    } catch (e) {
        console.log('[discover] could not load ' + className + ': ' + e);
        return;
    }

    console.log('[discover] === ' + className + ' ===');

    function describe(cls, label) {
        var methods = null;
        try {
            methods = cls.class.getDeclaredMethods();
        } catch (e) {
            return 0;
        }
        if (!methods) { return 0; }

        var count = 0;
        methods.forEach(function (method) {
            var name = method.getName();
            var paramTypes = method.getParameterTypes();
            var argSig = [];
            for (var i = 0; i < paramTypes.length; i++) {
                argSig.push(paramTypes[i].getName());
            }
            var ret = 'void';
            try { ret = method.getReturnType().getName(); } catch (e) { /* ignore */ }
            var isStatic = false;
            try { isStatic = (method.getModifiers() &
                Java.use('java.lang.reflect.Modifier').STATIC) !== 0; } catch (e) { /* ignore */ }

            console.log('[discover] ' + label + name + '(' + argSig.join(', ') +
                        ') -> ' + ret + (isStatic ? '  [static]' : ''));
            count++;
        });
        return count;
    }

    var total = describe(klass, '');

    var superClass = null;
    try {
        superClass = klass.class.getSuperclass();
    } catch (e) { /* ignore */ }
    while (superClass !== null) {
        try {
            var superWrapper = Java.use(superClass.getName());
            total += describe(superWrapper, superClass.getSimpleName() + '.');
        } catch (e) { /* ignore */ }
        try {
            superClass = superClass.getSuperclass();
        } catch (e) { break; }
    }

    console.log('[discover] ' + total + ' methods');
});
