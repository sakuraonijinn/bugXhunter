/*
 * ssl_pinning_bypass.js
 *
 * Purpose: defeat certificate pinning so the target's traffic can be
 *          inspected. Hooks the platform trust manager and the OkHttp
 *          and Conscrypt paths that enforce pinning.
 *
 * Reports: every pinned host it intercepts, and any validation failure
 *          it suppresses.
 *
 * Run:  frida -U -n com.example.app -l ssl_pinning_bypass.js
 *       (or: xbug hooks run ssl_pinning_bypass --target com.example.app)
 *
 * Scope: this is what the target's own traffic looks like to the
 * operating device. Only run against applications you are authorised to
 * test.
 */

'use strict';

Java.perform(function () {
    var reported = {};

    function report(kind, detail) {
        var key = kind + '|' + detail;
        if (reported[key]) { return; }
        reported[key] = true;
        console.log('[ssl-pinning] ' + kind + ': ' + detail);
    }

    // ------------------------------------------------------------------
    // OkHttp CertificatePinner
    // ------------------------------------------------------------------
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, peerCertificates) {
                report('okhttp-bypass', hostname);
                var empty = Java.use('java.util.ArrayList');
                return empty.$new();
            };
    } catch (e) {
        // OkHttp not present, or a different version. Keep going.
    }

    // ------------------------------------------------------------------
    // Conscrypt / Android TrustManager
    // ------------------------------------------------------------------
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        var checkTrustedRecursive = TrustManagerImpl.checkTrustedRecursive;
        checkTrustedRecursive.implementation = function () {
            report('conscrypt-bypass', 'checkTrustedRecursive');
            var X509Certificate = Java.use('java.security.cert.X509Certificate');
            return Java.array('java.security.cert.X509Certificate', [X509Certificate.$new()]);
        };
    } catch (e) { /* not present */ }

    try {
        var X509TrustManagerImpl = Java.use('com.android.org.conscrypt.X509TrustManagerImpl');
        X509TrustManagerImpl.checkTrustedRecursive.implementation = function () {
            report('conscrypt-bypass', 'X509TrustManagerImpl');
            var X509Certificate = Java.use('java.security.cert.X509Certificate');
            return Java.array('java.security.cert.X509Certificate', [X509Certificate.$new()]);
        };
    } catch (e) { /* not present */ }

    // The generic trust manager path, used by most HTTP clients.
    try {
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        TrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String')
            .implementation = function (chain, authType) {
                report('trustmanager-bypass', authType);
            };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // OkHttp CertificateChainCleaner, which is the other way OkHttp
    // enforces pinning.
    // ------------------------------------------------------------------
    try {
        var CertificateChainCleaner = Java.use('okhttp3.internal.tls.CertificateChainCleaner');
        CertificateChainCleaner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, peerCertificates) {
                report('okhttp-cleaner-bypass', hostname);
                var ArrayList = Java.use('java.util.ArrayList');
                return ArrayList.$new();
            };
    } catch (e) { /* not present */ }

    console.log('[ssl-pinning] hooks installed');
});
