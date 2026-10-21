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
        FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
            report(path, 'read');
            return this.$init(path);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // java.io.FileOutputStream
    // ------------------------------------------------------------------
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overload('java.lang.String').implementation = function (path) {
            report(path, 'write');
            return this.$init(path);
        };
        FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function (path, append) {
            report(path, 'write' + (append ? '-append' : ''));
            return this.$init(path, append);
        };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // SQLite, the interesting one: what is actually being stored
    // ------------------------------------------------------------------
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            console.log('[file] sql: ' + sql);
            return this.execSQL(sql);
        };
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
            .implementation = function (sql, args) {
                console.log('[file] query: ' + sql);
                return this.rawQuery(sql, args);
            };
    } catch (e) { /* not present */ }

    // ------------------------------------------------------------------
    // java.io.File.delete, so you see cleanup too
    // ------------------------------------------------------------------
    try {
        var File = Java.use('java.io.File');
        File.delete.implementation = function () {
            report(this.getAbsolutePath(), 'delete');
            return this.delete();
        };
    } catch (e) { /* not present */ }

    console.log('[file] hooks installed');
});
