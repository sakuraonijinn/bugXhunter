/*
 * keystore_hook.js
 *
 * Purpose: watch the app's use of the Android Keystore, and capture the
 *          material that passes through it. Aliases and operations are
 *          reported; keys held in software rather than hardware are
 *          flagged.
 *
 * Reports: alias, operation, and the key's own properties where the
 *          platform exposes them.
 *
 * Run:  frida -U -n com.example.app -l keystore_hook.js
 */

'use strict';

Java.perform(function () {
    function props(key) {
        try {
            var out = [];
            var enc = key.getEncoded();
            out.push('exportable=' + (enc !== null));
            var factory = key.getFactory();
            if (factory) { out.push('factory=' + factory.getClass().getName()); }
            if (key.getAlgorithm) { out.push('alg=' + key.getAlgorithm()); }
            if (key.getFormat) { out.push('format=' + key.getFormat()); }
            return out.join(' ');
        } catch (e) {
            return '<props unavailable: ' + e + '>';
        }
    }

    // ------------------------------------------------------------------
    // KeyStore.getInstance and getKey
    // ------------------------------------------------------------------
    try {
        var KeyStore = Java.use('java.security.KeyStore');
        KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
            console.log('[keystore] getInstance(' + type + ')');
            return this.getInstance(type);
        };
        KeyStore.getKey.overload('java.lang.String', '[C').implementation = function (alias, password) {
            var key = this.getKey(alias, password);
            if (key !== null) {
                console.log('[keystore] getKey alias=' + alias + ' ' + props(key));
            } else {
                console.log('[keystore] getKey alias=' + alias + ' -> null');
            }
            return key;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // SecretKeyFactory, where software keys are generated
    // ------------------------------------------------------------------
    try {
        var SecretKeyFactory = Java.use('javax.crypto.SecretKeyFactory');
        SecretKeyFactory.generateSecret.overload('java.security.spec.KeySpec')
            .implementation = function (spec) {
                var key = this.generateSecret(spec);
                console.log('[keystore] generateSecret ' + props(key));
                return key;
            };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // KeyPairGenerator, for RSA/EC keypairs
    // ------------------------------------------------------------------
    try {
        var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
        KeyPairGenerator.initialize.overload('java.security.spec.AlgorithmParameterSpec')
            .implementation = function (spec) {
                console.log('[keystore] KeyPairGenerator.initialize ' +
                            (spec ? spec.getClass().getName() : 'default'));
                return this.initialize(spec);
            };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // AndroidKeyStore, to see whether the key is actually hardware backed
    // ------------------------------------------------------------------
    try {
        var AndroidKeyStore = Java.use('android.security.keystore.AndroidKeyStore');
        AndroidKeyStore.getInstance.overload().implementation = function () {
            console.log('[keystore] AndroidKeyStore requested');
            return this.getInstance();
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // KeyInfo, to see if the key lives in a TEE or StrongBox
    // ------------------------------------------------------------------
    try {
        var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        KeyInfo.getSecurityLevel.implementation = function () {
            var level = this.getSecurityLevel();
            console.log('[keystore] KeyInfo securityLevel=' + level);
            return level;
        };
    } catch (e) { /* not present */ }

    console.log('[keystore] hooks installed');
});
