'use strict';

const curveJs = require('curve25519-js');
const nodeCrypto = require('crypto');

const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);

const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!Buffer.isBuffer(privKey)) {
        throw new Error(`Invalid private key type: ${typeof privKey}`);
    }
    if (privKey.length !== 32) {
        throw new Error(`Incorrect private key length: ${privKey.length}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!Buffer.isBuffer(pubKey)) {
        throw new Error(`Invalid public key type: ${typeof pubKey}`);
    }
    if (!pubKey || ((pubKey.length !== 33 || pubKey[0] !== 5) && pubKey.length !== 32)) {
        throw new Error("Invalid public key");
    }
    return pubKey.length === 33 ? pubKey.slice(1) : pubKey;
}

exports.generateKeyPair = function() {
    try {
        if (typeof nodeCrypto.generateKeyPairSync === 'function') {
            const { publicKey: publicDerBytes, privateKey: privateDerBytes } = nodeCrypto.generateKeyPairSync(
                'x25519',
                {
                    publicKeyEncoding: { format: 'der', type: 'spki' },
                    privateKeyEncoding: { format: 'der', type: 'pkcs8' }
                }
            );
            const pubKey = Buffer.concat([Buffer.from([5]), publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length)]);
            const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);

            return { pubKey, privKey };
        } else {
            const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
            return {
                privKey: Buffer.from(keyPair.private),
                pubKey: Buffer.from(keyPair.public),
            };
        }
    } catch (error) {
        console.error("Key pair generation error:", error.message);
        return null;
    }
};

exports.calculateAgreement = function(pubKey, privKey) {
    try {
        pubKey = scrubPubKeyFormat(pubKey);
        validatePrivKey(privKey);
        if (!pubKey || pubKey.length !== 32) {
            throw new Error("Invalid public key");
        }

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

            return nodeCrypto.diffieHellman({
                privateKey: nodePrivateKey,
                publicKey: nodePublicKey,
            });
        } else {
            return Buffer.from(curveJs.sharedKey(privKey, pubKey));
        }
    } catch (error) {
        console.error("Agreement calculation error:", error.message);
        return null;
    }
};

exports.calculateSignature = function(privKey, message) {
    try {
        validatePrivKey(privKey);
        if (!message) {
            throw new Error("Invalid message");
        }
        return Buffer.from(curveJs.sign(privKey, message));
    } catch (error) {
        console.error("Signature calculation error:", error.message);
        return null;
    }
};

exports.verifySignature = function(pubKey, msg, sig) {
    try {
        pubKey = scrubPubKeyFormat(pubKey);
        if (!pubKey || pubKey.length !== 32) {
            throw new Error("Invalid public key");
        }
        if (!msg) {
            throw new Error("Invalid message");
        }
        if (!sig || sig.length !== 64) {
            throw new Error("Invalid signature");
        }
        return curveJs.verify(pubKey, msg, sig);
    } catch (error) {
        console.error("Signature verification error:", error.message);
        return false;
    }
};