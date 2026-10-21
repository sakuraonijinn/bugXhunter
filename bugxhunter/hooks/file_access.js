/*
 * file_access.js
 *
 * Purpose: watch what the app reads and writes on disk, which is how
 *          you find unencrypted local storage, cached credentials and
 *          database files written in the clear.
 *
 * Reports: the path, the operation, and for writes the byte count.
 *
 * Run:  frida -U -n com.example.app -l file_access.js
 */

'use strict';

Java.perform(function () {
    var INTERESTING = /\.(sqlite|db|json|xml|key|pem|cer|crt|dat|log|so)$/i;

    function report(path, op, extra) {
        var p = String(path);
        if (p.indexOf('/proc/') === 0 || p.indexOf('/sys/') === 0) { return; }
        if (!INTERESTING.test(p) && p.indexOf('/data/data/') !== 0) { return; }
        console.log('[file] ' + op + ' ' + p + (extra ? ' ' + extra : ''));
    }

    // ------------------------------------------------------------------
    // java.io.FileInputStream
    // ------------------------------------------------------------------
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        var fisInit = FileInputStream.$init.overload('java.lang.String');
        fisInit.implementation = function (path) {
            report(path, 'read');
            return fisInit.call(this, path);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // java.io.FileOutputStream
    // ------------------------------------------------------------------
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        var fosInit = FileOutputStream.$init.overload('java.lang.String');
        fosInit.implementation = function (path) {
            report(path, 'write');
            return fosInit.call(this, path);
        };
        var fosInitAppend = FileOutputStream.$init.overload('java.lang.String', 'boolean');
        fosInitAppend.implementation = function (path, append) {
            report(path, 'write' + (append ? '-append' : ''));
            return fosInitAppend.call(this, path, append);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // SQLite, the interesting one: what is actually being stored
    // ------------------------------------------------------------------
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        var execSQL = SQLiteDatabase.execSQL.overload('java.lang.String');
        execSQL.implementation = function (sql) {
            console.log('[file] sql: ' + sql);
            return execSQL.call(this, sql);
        };
        var rawQuery = SQLiteDatabase.rawQuery.overload(
            'java.lang.String', '[Ljava.lang.String;');
        rawQuery.implementation = function (sql, args) {
            console.log('[file] query: ' + sql);
            return rawQuery.call(this, sql, args);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // java.io.File.delete, so you see cleanup too
    // ------------------------------------------------------------------
    try {
        var File = Java.use('java.io.File');
        var del = File.delete.overload();
        del.implementation = function () {
            report(this.getAbsolutePath(), 'delete');
            return del.call(this);
        };
    } catch (e) { /* not present */ }

    console.log('[file] hooks installed');
});
