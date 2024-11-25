/* eslint-disable */
// vim: ts=4:sw=4

const BaseKeyType = require('./base_key_type');

const CLOSED_SESSIONS_MAX = 40;
const SESSION_RECORD_VERSION = 'v1';

function assertBuffer(value) {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError("Buffer required");
    }
}

class SessionEntry {
    constructor() {
        this._chains = {};
    }

    toString() {
        const baseKey = this.indexInfo?.baseKey?.toString('base64');
        return `<SessionEntry [baseKey=${baseKey}]>`;
    }

    inspect() {
        return this.toString();
    }

    addChain(key, value) {
        assertBuffer(key);
        const id = key.toString('base64');
        if (this._chains[id]) {
            throw new Error("Overwrite attempt");
        }
        this._chains[id] = value;
    }

    getChain(key) {
        assertBuffer(key);
        return this._chains[key.toString('base64')];
    }

    deleteChain(key) {
        assertBuffer(key);
        const id = key.toString('base64');
        if (!(id in this._chains)) {
            throw new ReferenceError("Not Found");
        }
        delete this._chains[id];
    }

    *chains() {
        for (const [k, v] of Object.entries(this._chains)) {
            yield [Buffer.from(k, 'base64'), v];
        }
    }

    serialize() {
        const { registrationId, currentRatchet, indexInfo, pendingPreKey } = this;
        const data = {
            registrationId,
            currentRatchet: {
                ephemeralKeyPair: {
                    pubKey: currentRatchet.ephemeralKeyPair.pubKey.toString('base64'),
                    privKey: currentRatchet.ephemeralKeyPair.privKey.toString('base64')
                },
                lastRemoteEphemeralKey: currentRatchet.lastRemoteEphemeralKey.toString('base64'),
                previousCounter: currentRatchet.previousCounter,
                rootKey: currentRatchet.rootKey.toString('base64')
            },
            indexInfo: {
                baseKey: indexInfo.baseKey.toString('base64'),
                baseKeyType: indexInfo.baseKeyType,
                closed: indexInfo.closed,
                used: indexInfo.used,
                created: indexInfo.created,
                remoteIdentityKey: indexInfo.remoteIdentityKey.toString('base64')
            },
            _chains: this._serializeChains(this._chains)
        };

        if (pendingPreKey) {
            data.pendingPreKey = {
                ...pendingPreKey,
                baseKey: pendingPreKey.baseKey.toString('base64')
            };
        }

        return data;
    }

    static deserialize(data) {
        const obj = new this();
        obj.registrationId = data.registrationId;
        obj.currentRatchet = {
            ephemeralKeyPair: {
                pubKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.pubKey, 'base64'),
                privKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.privKey, 'base64')
            },
            lastRemoteEphemeralKey: Buffer.from(data.currentRatchet.lastRemoteEphemeralKey, 'base64'),
            previousCounter: data.currentRatchet.previousCounter,
            rootKey: Buffer.from(data.currentRatchet.rootKey, 'base64')
        };
        obj.indexInfo = {
            baseKey: Buffer.from(data.indexInfo.baseKey, 'base64'),
            baseKeyType: data.indexInfo.baseKeyType,
            closed: data.indexInfo.closed,
            used: data.indexInfo.used,
            created: data.indexInfo.created,
            remoteIdentityKey: Buffer.from(data.indexInfo.remoteIdentityKey, 'base64')
        };
        obj._chains = this._deserializeChains(data._chains);
        if (data.pendingPreKey) {
            obj.pendingPreKey = {
                ...data.pendingPreKey,
                baseKey: Buffer.from(data.pendingPreKey.baseKey, 'base64')
            };
        }
        return obj;
    }

    _serializeChains(chains) {
        const r = {};
        for (const [key, c] of Object.entries(chains)) {
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: c.chainKey.key?.toString('base64')
                },
                chainType: c.chainType,
                messageKeys: Object.fromEntries(
                    Object.entries(c.messageKeys).map(([idx, key]) => [idx, key.toString('base64')])
                )
            };
        }
        return r;
    }

    static _deserializeChains(chainsData) {
        const r = {};
        for (const [key, c] of Object.entries(chainsData)) {
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: c.chainKey.key ? Buffer.from(c.chainKey.key, 'base64') : undefined
                },
                chainType: c.chainType,
                messageKeys: Object.fromEntries(
                    Object.entries(c.messageKeys).map(([idx, key]) => [idx, Buffer.from(key, 'base64')])
                )
            };
        }
        return r;
    }
}

const migrations = [{
    version: 'v1',
    migrate(data) {
        const sessions = data._sessions;
        if (data.registrationId) {
            for (const session of Object.values(sessions)) {
                if (!session.registrationId) {
                    session.registrationId = data.registrationId;
                }
            }
        } else {
            for (const session of Object.values(sessions)) {
                if (session.indexInfo.closed === -1) {
                    console.error('V1 session storage migration error: registrationId',
                        data.registrationId, 'for open session version',
                        data.version);
                }
            }
        }
    }
}];

class SessionRecord {
    static createEntry() {
        return new SessionEntry();
    }

    static migrate(data) {
        let run = (data.version === undefined);
        for (const migration of migrations) {
            if (run) {
                console.info("Migrating session to:", migration.version);
                migration.migrate(data);
            } else if (migration.version === data.version) {
                run = true;
            }
        }
        if (!run) {
            throw new Error("Error migrating SessionRecord");
        }
    }

    static deserialize(data) {
        if (data.version !== SESSION_RECORD_VERSION) {
            this.migrate(data);
        }
        const obj = new this();
        if (data._sessions) {
            for (const [key, entry] of Object.entries(data._sessions)) {
                obj.sessions[key] = SessionEntry.deserialize(entry);
            }
        }
        return obj;
    }

    constructor() {
        this.sessions = {};
        this.version = SESSION_RECORD_VERSION;
    }

    serialize() {
        const _sessions = {};
        for (const [key, entry] of Object.entries(this.sessions)) {
            _sessions[key] = entry.serialize();
        }
        return {
            _sessions,
            version: this.version
        };
    }

    haveOpenSession() {
        return !!this.getOpenSession()?.registrationId;
    }

    getSession(key) {
        assertBuffer(key);
        this.detectDuplicateOpenSessions();
        const session = this.sessions[key.toString('base64')];
        if (session?.indexInfo.baseKeyType === BaseKeyType.OURS) {
            throw new Error("Tried to lookup a session using our basekey");
        }
        return session;
    }

    getOpenSession() {
        this.detectDuplicateOpenSessions();
        return Object.values(this.sessions).find(session => !this.isClosed(session));
    }

    setSession(session) {
        this.sessions[session.indexInfo.baseKey.toString('base64')] = session;
    }

    getSessions() {
        return Object.values(this.sessions).sort((a, b) => (b.indexInfo.used || 0) - (a.indexInfo.used || 0));
    }

    closeSession(session) {
        if (this.isClosed(session)) {
            console.warn("Session already closed", session);
            return;
        }
        session.indexInfo.closed = Date.now();
    }

    openSession(session) {
        if (!this.isClosed(session)) {
            console.warn("Session already open");
        }
        session.indexInfo.closed = -1;
    }

    isClosed(session) {
        return session.indexInfo.closed !== -1;
    }

    updateSessionState(session) {
        this.setSession(session);
        this.removeOldSessions();
    }

    archiveCurrentState() {
        const openSession = this.getOpenSession();
        if (openSession) {
            this.closeSession(openSession);
            this.updateSessionState(openSession);
        }
    }

    removeOldSessions() {
        while (Object.keys(this.sessions).length > CLOSED_SESSIONS_MAX) {
            let oldestKey;
            let oldestSession;
            for (const [key, session] of Object.entries(this.sessions)) {
                if (session.indexInfo.closed !== -1 &&
                    (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)) {
                    oldestKey = key;
                    oldestSession = session;
                }
            }
            if (oldestKey) {
                delete this.sessions[oldestKey];
            } else {
                throw new Error('Corrupt sessions object');
            }
        }
    }

    deleteAllSessions() {
        this.sessions = {};
    }

    detectDuplicateOpenSessions() {
        let openSession;
        for (const session of Object.values(this.sessions)) {
            if (!this.isClosed(session)) {
                if (openSession) {
                    throw new Error("Datastore inconsistency: multiple open sessions");
                }
                openSession = session;
            }
        }
    }
}

module.exports = SessionRecord;