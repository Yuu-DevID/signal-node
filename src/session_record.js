const BaseKeyType = require('./base_key_type');
const { assertBuffer } = require('./utils'); // Assuming assertBuffer is defined in a utility file

const CLOSED_SESSIONS_MAX = 40;
const SESSION_RECORD_VERSION = 'v1';

class SessionEntry {
    constructor() {
        this._chains = {};
    }

    toString() {
        const baseKey = this.indexInfo?.baseKey?.toString('base64');
        return `<SessionEntry [baseKey=${baseKey}]>`;
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
        if (!this._chains[key.toString('base64')]) {
            throw new ReferenceError("Not Found");
        }
        delete this._chains[key.toString('base64')];
    }

    *chains() {
        for (const [k, v] of Object.entries(this._chains)) {
            yield [Buffer.from(k, 'base64'), v];
        }
    }

    serialize() {
        const data = {
            registrationId: this.registrationId,
            currentRatchet: {
                ephemeralKeyPair: {
                    pubKey: this.currentRatchet.ephemeralKeyPair.pubKey.toString('base64'),
                    privKey: this.currentRatchet.ephemeralKeyPair.privKey.toString('base64')
                },
                lastRemoteEphemeralKey: this.currentRatchet.lastRemoteEphemeralKey.toString('base64'),
                previousCounter: this.currentRatchet.previousCounter,
                rootKey: this.currentRatchet.rootKey.toString('base64')
            },
            indexInfo: {
                baseKey: this.indexInfo.baseKey.toString('base64'),
                baseKeyType: this.indexInfo.baseKeyType,
                closed: this.indexInfo.closed,
                used: this.indexInfo.used,
                created: this.indexInfo.created,
                remoteIdentityKey: this.indexInfo.remoteIdentityKey.toString('base64')
            },
            _chains: this._serializeChains(this._chains)
        };
        if (this.pendingPreKey) {
            data.pendingPreKey = {
                ...this.pendingPreKey,
                baseKey: this.pendingPreKey.baseKey.toString('base64')
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
        const serializedChains = {};
        for (const key of Object.keys(chains)) {
            const chain = chains[key];
            const serializedMessageKeys = {};
            for (const [idx, key] of Object.entries(chain.messageKeys)) {
                serializedMessageKeys[idx] = key.toString('base64');
            }
            serializedChains[key] = {
                chainKey: {
                    counter: chain.chainKey.counter,
                    key: chain.chainKey.key?.toString('base64')
                },
                chainType: chain.chainType,
                messageKeys: serializedMessageKeys
            };
        }
        return serializedChains;
    }

    static _deserializeChains(chainsData) {
        const deserializedChains = {};
        for (const key of Object.keys(chainsData)) {
            const chainData = chainsData[key];
            const deserializedMessageKeys = {};
            for (const [idx, key] of Object.entries(chainData.messageKeys)) {
                deserializedMessageKeys[idx] = Buffer.from(key, 'base64');
            }
            deserializedChains[key] = {
                chainKey: {
                    counter: chainData.chainKey.counter,
                    key: chainData.chainKey.key ? Buffer.from(chainData.chainKey.key, 'base64') : undefined
                },
                chainType: chainData.chainType,
                messageKeys: deserializedMessageKeys
            };
        }
        return deserializedChains;
    }
}

const migrations = [{
    version: 'v1',
    migrate: function migrateV1(data) {
        const sessions = data._sessions;
        if (data.registrationId) {
            for (const key in sessions) {
                if (!sessions[key].registrationId) {
                    sessions[key].registrationId = data.registrationId;
                }
            }
        } else {
            for (const key in sessions) {
                if (sessions[key].indexInfo.closed === -1) {
                    console.error(`V1 session storage migration error: registrationId ${data.registrationId} for open session version ${data.version}`);
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
        for (let i = 0; i < migrations.length; ++i) {
            if (run) {
                console.info("Migrating session to:", migrations[i].version);
                migrations[i].migrate(data);
            } else if (migrations[i].version === data.version) {
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
        const serializedSessions = {};
        for (const [key, entry] of Object.entries(this.sessions)) {
            serializedSessions[key] = entry.serialize();
        }
        return {
            _sessions: serializedSessions,
            version: this.version
        };
    }

    haveOpenSession() {
        const openSession = this.getOpenSession();
        return (!!openSession && typeof openSession.registrationId === 'number');
    }

    getSession(key) {
        assertBuffer(key);
        const session = this.sessions[key.toString('base64')];
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            throw new Error("Tried to lookup a session using our basekey");
        }
        return session;
    }

    getOpenSession() {
        for (const session of Object.values(this.sessions)) {
            if (!this.isClosed(session)) {
                return session;
            }
        }
    }

    setSession(session) {
        this.sessions[session.indexInfo.baseKey.toString('base64')] = session;
    }

    getSessions() {
        // Return sessions ordered with most recently used first.
        return Object.values(this.sessions).sort((a, b) => (a.indexInfo.used || 0) - (b.indexInfo.used || 0));
    }

    closeSession(session) {
        if (this.isClosed(session)) {
            console.warn("Session already closed");
            return;
        }
        console.info("Closing session");
        session.indexInfo.closed = Date.now();
    }

    openSession(session) {
        if (!this.isClosed(session)) {
            console.warn("Session already open");
        }
        console.info("Opening session");
        session.indexInfo.closed = -1;
    }

    isClosed(session) {
        return session.indexInfo.closed !== -1;
    }

    removeOldSessions() {
        const CLOSED_SESSIONS_MAX = 100
        while (Object.keys(this.sessions).length > CLOSED_SESSIONS_MAX) {
            let oldestKey = null;
            let oldestSession = null;
            for (const [key, session] of Object.entries(this.sessions)) {
                if (session.indexInfo.closed !== -1 &&
                    (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)) {
                    oldestKey = key;
                    oldestSession = session;
                }
            }
            if (oldestKey) {
                console.info("Removing old closed session");
                delete this.sessions[oldestKey];
            } else {
                throw new Error('Corrupt sessions object');
            }
        }
    }

    deleteAllSessions() {
        this.sessions = {}; 
        console.info("All sessions deleted");
    }
}

module.exports = SessionRecord;
