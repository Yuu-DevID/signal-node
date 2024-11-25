'use strict';

const crypto = require('./crypto.js');

const VERSION = 0;

function iterateHash(data, key, count) {
    let result = crypto.hash(Buffer.concat([data, key]));
    for (let i = 1; i < count; i++) {
        result = crypto.hash(Buffer.concat([result, key]));
    }
    return result;
}

function shortToArrayBuffer(number) {
    const buffer = Buffer.alloc(2);
    buffer.writeUInt16BE(number);
    return buffer;
}

function getEncodedChunk(hash, offset) {
    const chunk =
        (hash[offset] << 32) +
        (hash[offset + 1] << 24) +
        (hash[offset + 2] << 16) +
        (hash[offset + 3] << 8) +
        hash[offset + 4];
    const value = Math.abs(chunk % 100000).toString().padStart(5, '0');
    return value;
}

function getDisplayStringFor(identifier, key, iterations) {
    const buffer = Buffer.concat([shortToArrayBuffer(VERSION), key, identifier]);
    const hashed = iterateHash(buffer, key, iterations);
    const output = new Uint8Array(hashed);

    return (
        getEncodedChunk(output, 0) +
        getEncodedChunk(output, 5) +
        getEncodedChunk(output, 10) +
        getEncodedChunk(output, 15) +
        getEncodedChunk(output, 20) +
        getEncodedChunk(output, 25)
    );
}

class FingerprintGenerator {
    constructor(iterations) {
        if (typeof iterations !== 'number' || iterations <= 0) {
            throw new Error('Iterations must be a positive number.');
        }
        this.iterations = iterations;
    }

    async createFor(localIdentifier, localIdentityKey, remoteIdentifier, remoteIdentityKey) {
        if (
            typeof localIdentifier !== 'string' ||
            typeof remoteIdentifier !== 'string' ||
            !(localIdentityKey instanceof Buffer) ||
            !(remoteIdentityKey instanceof Buffer)
        ) {
            throw new TypeError('Invalid arguments provided.');
        }

        const [localFingerprint, remoteFingerprint] = await Promise.all([
            getDisplayStringFor(localIdentifier, localIdentityKey, this.iterations),
            getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this.iterations),
        ]);

        return [localFingerprint, remoteFingerprint].sort().join('');
    }
}

exports.FingerprintGenerator = FingerprintGenerator;
