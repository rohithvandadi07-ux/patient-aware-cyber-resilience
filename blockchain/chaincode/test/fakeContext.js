'use strict';

// A hand-built fake chaincode stub/context -- no Fabric network, no
// fabric-shim test harness dependency. Faithful enough to the real
// ChaincodeStub API (getState/putState/getTxID/createCompositeKey/
// getStateByPartialCompositeKey) for these unit tests to exercise the
// contract's actual logic, including composite-key iteration.

const NUL = '\u0000';

class FakeChaincodeStub {
    constructor() {
        this._state = new Map();
        this._txCounter = 0;
    }

    async getState(key) {
        const value = this._state.get(key);
        return value === undefined ? Buffer.alloc(0) : value;
    }

    async putState(key, value) {
        this._state.set(key, value);
    }

    async deleteState(key) {
        this._state.delete(key);
    }

    getTxID() {
        this._txCounter += 1;
        return `fake-tx-${this._txCounter}`;
    }

    // Mirrors Fabric's real composite-key encoding closely enough for
    // prefix-based lookups in getStateByPartialCompositeKey to work the
    // same way the real ledger's would.
    createCompositeKey(objectType, attributes) {
        let key = NUL + objectType;
        for (const attr of attributes) {
            key += NUL + attr;
        }
        return key + NUL;
    }

    async getStateByPartialCompositeKey(objectType, attributes) {
        // Keep the trailing NUL delimiter from createCompositeKey -- it is
        // what stops "INC-1" from matching "INC-10". Stripping it (an
        // earlier version of this fake did) silently reintroduces the
        // exact prefix-collision bug the composite-key scheme exists to
        // prevent, and the one test case guarding against it would pass
        // for the wrong reason (there'd be nothing to strip to cause harm)
        // on a single-attribute collision only if the delimiter is kept.
        const prefix = this.createCompositeKey(objectType, attributes);
        const matches = [];
        for (const [key, value] of this._state.entries()) {
            if (key.startsWith(prefix)) {
                matches.push({ key, value });
            }
        }
        let index = 0;
        return {
            async next() {
                if (index >= matches.length) {
                    return { done: true };
                }
                const result = { value: matches[index], done: false };
                index += 1;
                return result;
            },
            async close() {
                return undefined;
            },
        };
    }
}

class FakeContext {
    constructor() {
        this.stub = new FakeChaincodeStub();
    }
}

module.exports = { FakeContext, FakeChaincodeStub };
