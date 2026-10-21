/*
 * crypto_hook.js
 *
 * Purpose: capture the material the app encrypts and decrypts, without
 *          changing what it does. Hooks the JCA cipher and MessageDigest
 *          entry points.
 *
 * Reports: algorithm, mode, padding, the key as hex, and the plaintext
 *          for the block cipher modes.
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

    function failed(what, e) {
        console.log('[crypto] skipped ' + what + ': ' + e);
    }

    // ------------------------------------------------------------------
    // Cipher.getInstance
    // ------------------------------------------------------------------
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var getInstance = Cipher.getInstance.overload('java.lang.String');
        getInstance.implementation = function (transformation) {
            console.log('[crypto] Cipher.getInstance("' + transformation + '")');
            return getInstance.call(this, transformation);
        };
    } catch (e) {
        failed('Cipher.getInstance', e);
    }

    // ------------------------------------------------------------------
    // Cipher.init(int, Key)
    // ------------------------------------------------------------------
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var init = Cipher.init.overload('int', 'java.security.Key');
        init.implementation = function (mode, key) {
            console.log('[crypto] Cipher.init mode=' + mode +
                        ' algorithm=' + this.getAlgorithm() +
                        ' key=' + keyToHex(key));
            return init.call(this, mode, key);
        };
    } catch (e) {
        failed('Cipher.init(int, Key)', e);
    }

    // ------------------------------------------------------------------
    // Cipher.doFinal(byte[])
    //
    // The algorithm and mode are read from the cipher itself, not from
    // the arguments, because doFinal takes none.
    // ------------------------------------------------------------------
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var doFinal = Cipher.doFinal.overload('[B');
        doFinal.implementation = function (input) {
            var out = doFinal.call(this, input);
            var algorithm = '';
            var mode = '';
            try { algorithm = String(this.getAlgorithm()); } catch (e) { /* ignore */ }
            try { mode = String(this.getMode()); } catch (e) { /* ignore */ }
            console.log('[crypto] doFinal alg=' + algorithm +
                        ' mode=' + mode +
                        ' in=' + toHex(input) +
                        ' out=' + toHex(out));
            return out;
        };
    } catch (e) {
        failed('Cipher.doFinal(byte[])', e);
    }

    // ------------------------------------------------------------------
    // SecretKeySpec, the usual place a key is built
    // ------------------------------------------------------------------
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        var keySpecInit = SecretKeySpec.$init.overload('[B', 'java.lang.String');
        keySpecInit.implementation = function (key, algorithm) {
            console.log('[crypto] SecretKeySpec alg=' + algorithm +
                        ' key=' + toHex(key));
            return keySpecInit.call(this, key, algorithm);
        };
    } catch (e) {
        failed('SecretKeySpec(byte[], String)', e);
    }

    // ------------------------------------------------------------------
    // MessageDigest.digest(byte[])
    // ------------------------------------------------------------------
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        var digest = MessageDigest.digest.overload('[B');
        digest.implementation = function (input) {
            var out = digest.call(this, input);
            console.log('[crypto] MessageDigest ' + this.getAlgorithm() +
                        ' in=' + toHex(input) +
                        ' out=' + toHex(out));
            return out;
        };
    } catch (e) {
        failed('MessageDigest.digest(byte[])', e);
    }

    // ------------------------------------------------------------------
    // android.util.Base64, very common in app-level crypto
    // ------------------------------------------------------------------
    try {
        var Base64 = Java.use('android.util.Base64');
        var encode = Base64.encodeToString.overload('[B', 'int');
        encode.implementation = function (input, flags) {
            var out = encode.call(this, input, flags);
            console.log('[crypto] Base64.encodeToString -> ' + out);
            return out;
        };
    } catch (e) {
        failed('android.util.Base64.encodeToString', e);
    }

    console.log('[crypto] hooks installed');
});
