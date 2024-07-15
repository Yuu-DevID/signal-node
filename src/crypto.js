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
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

function decrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}

function calculateMAC(key, data) {
    assertBuffer(key);
    assertBuffer(data);
    return crypto.createHmac('sha256', key).update(data).digest();
}

function hash(data) {
    assertBuffer(data);
    return crypto.createHash('sha512').update(data).digest();
}

// Salts always end up being 32 bytes
function deriveSecrets(input, salt, info, chunks = 3) {
    assertBuffer(input);
    assertBuffer(salt);
    assertBuffer(info);

    if (salt.length !== 32) {
        throw new Error("Got salt of incorrect length");
    }

    assert(chunks >= 1 && chunks <= 3);

    const PRK = calculateMAC(salt, input);
    const results = [];
    let previous = Buffer.alloc(0);

    for (let i = 1; i <= chunks; i++) {
        const hmacInput = Buffer.concat([previous, info, Buffer.from([i])]);
        previous = calculateMAC(PRK, hmacInput);
        results.push(previous);
    }

    return results;
}

function verifyMAC(data, key, mac, length) {
    const calculatedMac = calculateMAC(key, data).slice(0, length);
    if (mac.length !== length || !crypto.timingSafeEqual(mac, calculatedMac)) {
        throw new Error("Bad MAC");
    }
}

module.exports = {
    deriveSecrets,
    decrypt,
    encrypt,
    hash,
    calculateMAC,
    verifyMAC
};