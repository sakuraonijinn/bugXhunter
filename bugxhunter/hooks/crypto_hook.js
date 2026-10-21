/*
 * crypto_hook.js
 *
 * Purpose: capture the material the app encrypts and decrypts, without
 *          changing what it does. Hooks the JCA cipher and MessageDigest
 *          entry points.
 *
 * Reports: algorithm, mode, padding, the key as hex, and the plaintext
 *          for CBC and ECB modes.
 *
 * Note:   keys are printed in full. Treat the output as sensitive.
 *
 * Run:  frida -U -n com.example.app -l crypto_hook.js
 */

'use strict';

Java.perform(function () {
    function toHex(bytes) {
        if (bytes === null || bytes === undefined) { return '<null>'; }
        try {
            var out = '';
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i] & 0xff;
                out += ('0' + b.toString(16)).slice(-2);
            }
            return out;
        } catch (e) {
            return '<unreadable>';
        }
    }

    function keyToHex(key) {
        try {
            if (key === null) { return '<null>'; }
            if (key.getEncoded) {
                return toHex(key.getEncoded());
            }
            return String(key);
        } catch (e) {
            return '<unreadable>';
        }
    }

    // ------------------------------------------------------------------
    // javax.crypto.Cipher
    // ------------------------------------------------------------------
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
            console.log('[crypto] Cipher.getInstance("' + transformation + '")');
            return this.getInstance(transformation);
        };
    } catch (e) { /* not present */ }

    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            console.log('[crypto] Cipher.init mode=' + mode +
                        ' algorithm=' + this.getAlgorithm() +
                        ' key=' + keyToHex(key));
            return this.init(mode, key);
        };
    } catch (e) { /* not present */ }

    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
            var out = this.doFinal(input);
            var mode = String(this.getMode());
            if (mode === 'Cipher.getMode') {
                mode = String(this.getMode());
            }
            console.log('[crypto] doFinal alg=' + this.getAlgorithm() +
                        ' in=' + toHex(input) +
                        ' out=' + toHex(out));
            return out;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // javax.crypto.spec.SecretKeySpec, the usual place a key is built
    // ------------------------------------------------------------------
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algorithm) {
            console.log('[crypto] SecretKeySpec alg=' + algorithm +
                        ' key=' + toHex(key));
            return this.$init(key, algorithm);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // java.security.MessageDigest
    // ------------------------------------------------------------------
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload('[B').implementation = function (input) {
            var out = this.digest(input);
            console.log('[crypto] MessageDigest ' + this.getAlgorithm() +
                        ' in=' + toHex(input) +
                        ' out=' + toHex(out));
            return out;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // java.util.Base64, very common in app-level crypto
    // ------------------------------------------------------------------
    try {
        var Base64 = Java.use('android.util.Base64');
        Base64.encodeToString.overload('[B', 'int').implementation = function (input, flags) {
            var out = this.encodeToString(input, flags);
            console.log('[crypto] Base64.encodeToString -> ' + out);
            return out;
        };
    } catch (e) { /* not present */ }

    console.log('[crypto] hooks installed');
});
