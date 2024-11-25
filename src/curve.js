'use strict';

const curveJs = require('curve25519-js');
const nodeCrypto = require('crypto');

const PUBLIC_KEY_DER_PREFIX = Buffer.from([48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0]);
const PRIVATE_KEY_DER_PREFIX = Buffer.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32]);

// Helper function for validation
function validateBuffer(value, expectedLength, name) {
    if (!(value instanceof Buffer)) {
        throw new Error(`Invalid ${name}: expected Buffer, got ${typeof value}`);
    }
    if (value.byteLength !== expectedLength) {
        throw new Error(`Invalid ${name} length: expected ${expectedLength}, got ${value.byteLength}`);
    }
}

// Validates the private key
function validatePrivateKey(privKey) {
    validateBuffer(privKey, 32, 'private key');
}

// Scrubs and validates public key format
function scrubPublicKey(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key: expected Buffer, got ${typeof pubKey}`);
    }
    if (pubKey.byteLength === 33 && pubKey[0] === 5) {
        return pubKey.slice(1);
    } else if (pubKey.byteLength === 32) {
        console.warn("Unexpected public key format (length 32), please report the source of this key.");
        return pubKey;
    }
    throw new Error("Invalid public key format or length");
}

// Generate key pair
exports.generateKeyPair = function () {
    if (typeof nodeCrypto.generateKeyPairSync === 'function') {
        const { publicKey: publicDerBytes, privateKey: privateDerBytes } = nodeCrypto.generateKeyPairSync(
            'x25519',
            {
                publicKeyEncoding: { format: 'der', type: 'spki' },
                privateKeyEncoding: { format: 'der', type: 'pkcs8' }
            }
        );

        const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length - 1, PUBLIC_KEY_DER_PREFIX.length + 32);
        pubKey[0] = 5;

        const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);

        return { pubKey, privKey };
    } else {
        const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
        return {
            privKey: Buffer.from(keyPair.private),
            pubKey: Buffer.from(keyPair.public),
        };
    }
};

// Calculate shared secret
exports.calculateAgreement = function (pubKey, privKey) {
    pubKey = scrubPublicKey(pubKey);
    validatePrivateKey(privKey);

    if (typeof nodeCrypto.diffieHellman === 'function') {
        const nodePrivateKey = nodeCrypto.createPrivateKey({
            key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = nodeCrypto.createPublicKey({
            key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
            format: 'der',
            type: 'spki'
        });

        return nodeCrypto.diffieHellman({ privateKey: nodePrivateKey, publicKey: nodePublicKey });
    } else {
        const secret = curveJs.sharedKey(privKey, pubKey);
        return Buffer.from(secret);
    }
};

// Calculate signature
exports.calculateSignature = function (privKey, message) {
    validatePrivateKey(privKey);
    if (!message || !(message instanceof Buffer)) {
        throw new Error("Invalid message: expected a Buffer");
    }
    return Buffer.from(curveJs.sign(privKey, message));
};

// Verify signature
exports.verifySignature = function (pubKey, message, signature) {
    pubKey = scrubPublicKey(pubKey);

    if (!message || !(message instanceof Buffer)) {
        throw new Error("Invalid message: expected a Buffer");
    }
    validateBuffer(signature, 64, 'signature');

    return curveJs.verify(pubKey, message, signature);
};
