'use strict';

class ProtocolAddress {
    static from(encodedAddress) {
        if (typeof encodedAddress !== 'string' || !/^[\w-]+\.\d+$/.test(encodedAddress)) {
            throw new Error('Invalid address encoding. Expected format: "<id>.<deviceId>"');
        }
        const [id, deviceId] = encodedAddress.split('.');
        return new ProtocolAddress(id, Number(deviceId));
    }

    constructor(id, deviceId) {
        if (typeof id !== 'string' || id.includes('.')) {
            throw new TypeError('Invalid id. It must be a string without dots.');
        }
        if (!Number.isInteger(deviceId) || deviceId < 0) {
            throw new TypeError('deviceId must be a non-negative integer.');
        }
        this.id = id;
        this.deviceId = deviceId;
    }

    toString() {
        return `${this.id}.${this.deviceId}`;
    }

    is(other) {
        return (
            other instanceof ProtocolAddress &&
            this.id === other.id &&
            this.deviceId === other.deviceId
        );
    }
}

module.exports = ProtocolAddress;
