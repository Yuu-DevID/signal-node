// vim: ts=4:sw=4

'use strict';

const crypto = require('crypto');
const assert = require('assert');

function assertBuffer(value) {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError(`Expected Buffer instead of: ${typeof value}`);
    }
    return value;
}

function encrypt(key, data, iv) {
    try {
        assertBuffer(key);
        assertBuffer(data);
        assertBuffer(iv);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    } catch (error) {
        console.error("Encryption error:", error.message);
        return null;
    }
}

function decrypt(key, data, iv) {
    try {
        assertBuffer(key);
        assertBuffer(data);
        assertBuffer(iv);
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    } catch (error) {
        console.error("Decryption error:", error.message);
        return null;
    }
}

function calculateMAC(key, data) {
    try {
        assertBuffer(key);
        assertBuffer(data);
        return crypto.createHmac('sha256', key).update(data).digest();
    } catch (error) {
        console.error("MAC calculation error:", error.message);
        return null;
    }
}

function hash(data) {
    try {
        assertBuffer(data);
        return crypto.createHash('sha512').update(data).digest();
    } catch (error) {
        console.error("Hash error:", error.message);
        return null;
    }
}

function deriveSecrets(input, salt, info, chunks = 3) {
    try {
        assertBuffer(input);
        assertBuffer(salt);
        assertBuffer(info);

        if (salt.length !== 32) {
            throw new Error("Got salt of incorrect length");
        }

        assert(chunks >= 1 && chunks <= 3);

        const PRK = calculateMAC(salt, input);
        if (PRK === null) throw new Error("PRK calculation failed");

        const results = [];
        let previous = Buffer.alloc(0);

        for (let i = 1; i <= chunks; i++) {
            const hmacInput = Buffer.concat([previous, info, Buffer.from([i])]);
            previous = calculateMAC(PRK, hmacInput);
            if (previous === null) throw new Error("HMAC calculation failed");
            results.push(previous);
        }

        return results;
    } catch (error) {
        console.error("Secret derivation error:", error.message);
        return null;
    }
}

function verifyMAC(data, key, mac, length) {
    try {
        const calculatedMac = calculateMAC(key, data).slice(0, length);
        if (!calculatedMac || mac.length !== length || !crypto.timingSafeEqual(mac, calculatedMac)) {
            throw new Error("Bad MAC");
        }
    } catch (error) {
        console.error("MAC verification error:", error.message);
        return false;
    }
    return true;
}

module.exports = {
    deriveSecrets,
    decrypt,
    encrypt,
    hash,
    calculateMAC,
    verifyMAC
};