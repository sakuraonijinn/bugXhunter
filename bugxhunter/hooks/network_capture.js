/*
 * network_capture.js
 *
 * Purpose: show what the app sends and receives without needing a proxy
 *          in the path. Hooks OkHttp, HttpURLConnection and the
 *          WebView loader, and prints URL, method, headers and body
 *          size.
 *
 * Reports: one line per request, with a short body preview.
 *
 * Run:  frida -U -n com.example.app -l network_capture.js
 */

'use strict';

Java.perform(function () {
    function preview(bytes) {
        if (bytes === null || bytes === undefined) { return '<null>'; }
        try {
            var text = Java.use('java.lang.String').$new(bytes);
            var s = String(text);
            if (s.length > 300) { s = s.substring(0, 300) + '...'; }
            return s.replace(/\n/g, '\\n');
        } catch (e) {
            return '<binary ' + bytes.length + ' bytes>';
        }
    }

    function headersToString(map) {
        try {
            var out = [];
            var it = map.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                out.push(entry.getKey() + '=' + entry.getValue());
            }
            return out.join('; ');
        } catch (e) {
            return '<unreadable>';
        }
    }

    // ------------------------------------------------------------------
    // OkHttp Request / Response
    // ------------------------------------------------------------------
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var newCall = OkHttpClient.newCall.overload('okhttp3.Request');
        newCall.implementation = function (request) {
            try {
                var method = request.method();
                var url = request.url().toString();
                var headers = headersToString(request.headers());
                console.log('[net] okhttp ' + method + ' ' + url +
                            ' headers{' + headers + '}');
            } catch (e) { /* keep going */ }
            return newCall.call(this, request);
        };
    } catch (e) { /* OkHttp not present */ }

    try {
        var ResponseBody = Java.use('okhttp3.ResponseBody');
        var toString = ResponseBody.string.overload();
        toString.implementation = function () {
            var out = toString.call(this);
            console.log('[net] okhttp response body: ' +
                        out.substring(0, Math.min(out.length, 300)));
            return out;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // HttpURLConnection
    // ------------------------------------------------------------------
    try {
        var URL = Java.use('java.net.URL');
        var openConnection = URL.openConnection.overload();
        openConnection.implementation = function () {
            var conn = openConnection.call(this);
            console.log('[net] URL.openConnection ' + this.toString());
            return conn;
        };
    } catch (e) { /* not present */ }

    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        var getResponseCode = HttpURLConnection.getResponseCode.overload();
        getResponseCode.implementation = function () {
            var code = getResponseCode.call(this);
            console.log('[net] http ' + this.getRequestMethod() + ' ' +
                        this.getURL().toString() + ' -> ' + code);
            return code;
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // WebView
    // ------------------------------------------------------------------
    try {
        var WebView = Java.use('android.webkit.WebView');
        var loadUrl = WebView.loadUrl.overload('java.lang.String');
        loadUrl.implementation = function (url) {
            console.log('[net] WebView.loadUrl ' + url);
            return loadUrl.call(this, url);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // WebViewClient, which is where a lot of interesting URLs show up
    // ------------------------------------------------------------------
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        var onPageStarted = WebViewClient.onPageStarted.overload(
            'android.webkit.WebView', 'java.lang.String', 'android.graphics.Bitmap');
        onPageStarted.implementation = function (view, url, icon) {
            console.log('[net] onPageStarted ' + url);
            return onPageStarted.call(this, view, url, icon);
        };
    } catch (e) { /* not present */ }

    console.log('[net] hooks installed');
});
