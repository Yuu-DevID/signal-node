'use strict';

const BaseKeyType = require('./base_key_type');
const ChainType = require('./chain_type');
const SessionRecord = require('./session_record');
const crypto = require('./crypto');
const curve = require('./curve');
const errors = require('./errors');
const queueJob = require('./queue_job');
const Util = require('./util');

const SHARED_SECRET_SIZE = 32;
const MASTER_KEY_INFO = Buffer.from("WhisperText");
const RATCHET_INFO = Buffer.from("WhisperRatchet");

class SessionBuilder {
    constructor(storage, protocolAddress) {
        this.addr = protocolAddress;
        this.storage = storage;
    }

    async initOutgoing(device) {
        const fqAddr = this.addr.toString();
        return await queueJob(fqAddr, async () => {
            await this.validateDevice(device);
            const baseKey = curve.generateKeyPair();
            const session = await this.createSessionForOutgoing(device, baseKey);
            await this.updateSessionRecord(fqAddr, session);
        });
    }

    async validateDevice(device) {
        if (!await this.storage.isTrustedIdentity(this.addr.id, device.identityKey)) {
            throw new errors.UntrustedIdentityKeyError(this.addr.id, device.identityKey);
        }
        curve.verifySignature(device.identityKey, device.signedPreKey.publicKey, device.signedPreKey.signature);
    }

    async createSessionForOutgoing(device, baseKey) {
        const devicePreKey = device.preKey && device.preKey.publicKey;
        const session = await this.initSession(true, baseKey, undefined, device.identityKey,
            devicePreKey, device.signedPreKey.publicKey, device.registrationId);
        session.pendingPreKey = {
            signedKeyId: device.signedPreKey.keyId,
            baseKey: baseKey.pubKey,
            preKeyId: device.preKey ? device.preKey.keyId : undefined
        };
        return session;
    }

    async updateSessionRecord(fqAddr, session) {
        let record = await this.storage.loadSession(fqAddr) || new SessionRecord();
        const openSession = record.getOpenSession();
        record.archiveCurrentState();

        if (openSession && session && !Util.isEqual(openSession.indexInfo.remoteIdentityKey, session.indexInfo.remoteIdentityKey)) {
            console.warn("Deleting all sessions because identity has changed");
            record.deleteAllSessions();
        }

        record.updateSessionState(session);
        await this.storage.storeSession(fqAddr, record);
    }

    async initIncoming(record, message) {
        const fqAddr = this.addr.toString();
        if (!await this.storage.isTrustedIdentity(fqAddr, message.identityKey)) {
            throw new errors.UntrustedIdentityKeyError(this.addr.id, message.identityKey);
        }

        if (record.getSession(message.baseKey)) {
            return; // Session already exists
        }

        const [preKeyPair, signedPreKeyPair] = await this.loadPreKeys(message);
        const existingOpenSession = record.getOpenSession();

        if (!signedPreKeyPair) {
            if (existingOpenSession && existingOpenSession.currentRatchet) return;
            throw new errors.PreKeyError("Missing Signed PreKey for PreKeyWhisperMessage");
        }

        if (existingOpenSession) {
            record.archiveCurrentState();
        }

        if (message.preKeyId && !preKeyPair) {
            throw new errors.PreKeyError("Invalid PreKey ID");
        }

        const session = await this.initSession(false, preKeyPair, signedPreKeyPair,
            message.identityKey, message.baseKey, undefined, message.registrationId);

        if (existingOpenSession && session && !Util.isEqual(existingOpenSession.indexInfo.remoteIdentityKey, session.indexInfo.remoteIdentityKey)) {
            console.warn("Deleting all sessions because identity has changed");
            record.deleteAllSessions();
        }

        record.updateSessionState(session);
        return message.preKeyId;
    }

    async loadPreKeys(message) {
        return await Promise.all([
            this.storage.loadPreKey(message.preKeyId),
            this.storage.loadSignedPreKey(message.signedPreKeyId)
        ]);
    }

    async initSession(isInitiator, ourEphemeralKey, ourSignedKey, theirIdentityPubKey,
        theirEphemeralPubKey , theirSignedPubKey, registrationId) {
        if (isInitiator) {
            if (ourSignedKey) {
                throw new Error("Invalid call to initSession");
            }
            ourSignedKey = ourEphemeralKey;
        } else {
            if (theirSignedPubKey) {
                throw new Error("Invalid call to initSession");
            }
            theirSignedPubKey = theirEphemeralPubKey;
        }

        const sharedSecret = new Uint8Array(SHARED_SECRET_SIZE * (ourEphemeralKey && theirEphemeralPubKey ? 5 : 4));
        sharedSecret.fill(0xff);

        const ourIdentityKey = await this.storage.getOurIdentity();
        const a1 = curve.calculateAgreement(theirSignedPubKey, ourIdentityKey.privKey);
        const a2 = curve.calculateAgreement(theirIdentityPubKey, ourSignedKey.privKey);
        const a3 = curve.calculateAgreement(theirSignedPubKey, ourSignedKey.privKey);

        if (isInitiator) {
            sharedSecret.set(new Uint8Array(a1), SHARED_SECRET_SIZE);
            sharedSecret.set(new Uint8Array(a2), SHARED_SECRET_SIZE * 2);
        } else {
            sharedSecret.set(new Uint8Array(a1), SHARED_SECRET_SIZE * 2);
            sharedSecret.set(new Uint8Array(a2), SHARED_SECRET_SIZE);
        }

        sharedSecret.set(new Uint8Array(a3), SHARED_SECRET_SIZE * 3);

        if (ourEphemeralKey && theirEphemeralPubKey) {
            const a4 = curve.calculateAgreement(theirEphemeralPubKey, ourEphemeralKey.privKey);
            sharedSecret.set(new Uint8Array(a4), SHARED_SECRET_SIZE * 4);
        }

        const masterKey = crypto.deriveSecrets(Buffer.from(sharedSecret), Buffer.alloc(32), MASTER_KEY_INFO);
        const session = SessionRecord.createEntry();
        session.registrationId = registrationId;
        session.currentRatchet = {
            rootKey: masterKey[0],
            ephemeralKeyPair: isInitiator ? curve.generateKeyPair() : ourSignedKey,
            lastRemoteEphemeralKey: theirSignedPubKey,
            previousCounter: 0
        };
        session.indexInfo = {
            created: Date.now(),
            used: Date.now(),
            remoteIdentityKey: theirIdentityPubKey,
            baseKey: isInitiator ? ourEphemeralKey.pubKey : theirEphemeralPubKey,
            baseKeyType: isInitiator ? BaseKeyType.OURS : BaseKeyType.THEIRS,
            closed: -1
        };

        if (isInitiator) {
            this.calculateSendingRatchet(session, theirSignedPubKey);
        }

        return session;
    }

    calculateSendingRatchet(session, remoteKey) {
        const ratchet = session.currentRatchet;
        const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
        const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, RATCHET_INFO);
        session.addChain(ratchet.ephemeralKeyPair.pubKey, {
            messageKeys: {},
            chainKey: {
                counter: -1,
                key: masterKey[1]
            },
            chainType: ChainType.SENDING
        });
        ratchet.rootKey = masterKey[0];
    }
}

module.exports = SessionBuilder;