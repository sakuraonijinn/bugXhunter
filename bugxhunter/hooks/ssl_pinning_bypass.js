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
 * Note: each hook is in its own try block. A missing overload throws,
 *       and one failure must not stop the rest of the hooks from
 *       installing.
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

    function failed(what, e) {
        console.log('[ssl-pinning] skipped ' + what + ': ' + e);
    }

    // ------------------------------------------------------------------
    // OkHttp CertificatePinner
    // ------------------------------------------------------------------
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        var pinnerCheck = CertificatePinner.check.overload(
            'java.lang.String', 'java.util.List');
        pinnerCheck.implementation = function (hostname, peerCertificates) {
            report('okhttp-bypass', hostname);
            var ArrayList = Java.use('java.util.ArrayList');
            return ArrayList.$new();
        };
    } catch (e) {
        failed('okhttp3.CertificatePinner.check', e);
    }

    // ------------------------------------------------------------------
    // OkHttp CertificateChainCleaner, the other way OkHttp pins.
    // ------------------------------------------------------------------
    try {
        var CertificateChainCleaner = Java.use('okhttp3.internal.tls.CertificateChainCleaner');
        var cleanerCheck = CertificateChainCleaner.check.overload(
            'java.lang.String', 'java.util.List');
        cleanerCheck.implementation = function (hostname, peerCertificates) {
            report('okhttp-cleaner-bypass', hostname);
            var ArrayList = Java.use('java.util.ArrayList');
            return ArrayList.$new();
        };
    } catch (e) {
        failed('okhttp3.internal.tls.CertificateChainCleaner.check', e);
    }

    // ------------------------------------------------------------------
    // Conscrypt TrustManagerImpl
    //
    // checkTrustedRecursive has several overloads, so the one to hook
    // has to be named. This is the signature used by Android 7 and up.
    // ------------------------------------------------------------------
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        var checkRecursive = TrustManagerImpl.checkTrustedRecursive.overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.util.List',
            'java.security.cert.X509Certificate',
            'boolean');
        checkRecursive.implementation = function (chain, authType, chainPtr,
                                                 ocsp, isStaticClient) {
            report('conscrypt-bypass', 'TrustManagerImpl');
            var X509Certificate = Java.use('java.security.cert.X509Certificate');
            return Java.array('java.security.cert.X509Certificate',
                              [X509Certificate.$new()]);
        };
    } catch (e) {
        failed('com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive', e);
    }

    // ------------------------------------------------------------------
    // Conscrypt X509TrustManagerImpl
    // ------------------------------------------------------------------
    try {
        var X509TrustManagerImpl = Java.use('com.android.org.conscrypt.X509TrustManagerImpl');
        var x509Check = X509TrustManagerImpl.checkTrustedRecursive.overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.util.List',
            'java.security.cert.X509Certificate',
            'boolean');
        x509Check.implementation = function (chain, authType, chainPtr,
                                            ocsp, isStaticClient) {
            report('conscrypt-bypass', 'X509TrustManagerImpl');
            var X509Certificate = Java.use('java.security.cert.X509Certificate');
            return Java.array('java.security.cert.X509Certificate',
                              [X509Certificate.$new()]);
        };
    } catch (e) {
        failed('com.android.org.conscrypt.X509TrustManagerImpl.checkTrustedRecursive', e);
    }

    // ------------------------------------------------------------------
    // The generic trust manager path, used by most HTTP clients.
    // ------------------------------------------------------------------
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var checkServer = X509TrustManager.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;', 'java.lang.String');
        checkServer.implementation = function (chain, authType) {
            report('trustmanager-bypass', authType);
        };
    } catch (e) {
        failed('javax.net.ssl.X509TrustManager.checkServerTrusted', e);
    }

    // ------------------------------------------------------------------
    // HostnameVerifier, which apps use to check the certificate name
    // even after the chain has been accepted.
    // ------------------------------------------------------------------
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var verify = HostnameVerifier.verify.overload(
            'java.lang.String', 'javax.net.ssl.SSLSession');
        verify.implementation = function (hostname, session) {
            report('hostname-bypass', hostname);
            return true;
        };
    } catch (e) {
        failed('javax.net.ssl.HostnameVerifier.verify', e);
    }

    console.log('[ssl-pinning] hooks installed');
});
