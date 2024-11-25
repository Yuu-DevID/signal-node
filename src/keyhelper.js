'use strict';

const curve = require('./curve');
const nodeCrypto = require('crypto');

function isNonNegativeInteger(n) {
    return Number.isInteger(n) && n >= 0;
}

exports.generateIdentityKeyPair = curve.generateKeyPair;

exports.generateRegistrationId = function () {
    const randomBytes = nodeCrypto.randomBytes(2);
    const registrationId = new Uint16Array(randomBytes.buffer)[0];
    return registrationId & 0x3FFF;
};

exports.generateSignedPreKey = function (identityKeyPair, signedKeyId) {
    if (
        !(identityKeyPair.privKey instanceof Buffer) ||
        identityKeyPair.privKey.byteLength !== 32 ||
        !(identityKeyPair.pubKey instanceof Buffer) ||
        identityKeyPair.pubKey.byteLength !== 33
    ) {
        throw new TypeError('Invalid identityKeyPair: Expected private key (32 bytes) and public key (33 bytes).');
    }
    if (!isNonNegativeInteger(signedKeyId)) {
        throw new TypeError(`Invalid signedKeyId: Expected non-negative integer, got ${signedKeyId}.`);
    }

    const keyPair = curve.generateKeyPair();
    const signature = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey);

    return {
        keyId: signedKeyId,
        keyPair,
        signature,
    };
};

exports.generatePreKey = function (keyId) {
    if (!isNonNegativeInteger(keyId)) {
        throw new TypeError(`Invalid keyId: Expected non-negative integer, got ${keyId}.`);
    }

    const keyPair = curve.generateKeyPair();
    return {
        keyId,
        keyPair,
    };
};
