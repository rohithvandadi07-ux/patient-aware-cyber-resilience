'use strict';

const { Contract } = require('fabric-contract-api');

// Mirrors backend/app/schemas/enums.py exactly -- chaincode args are always
// strings, so these vocabularies are duplicated here (JS can't import a
// Python enum). If you add/rename a value in enums.py, update here too, or
// recordDecision/recordResponse will start rejecting valid categories.
const RESPONSE_ACTION_CATEGORIES = [
    'block_traffic',
    'revoke_session',
    'rotate_credentials',
    'restrict_communication',
    'isolate_non_critical',
    'isolate_critical',
    'quarantine_segment',
    'activate_backup',
    'restart_service',
    'failover',
    'shutdown',
];

const APPROVAL_DECISIONS = ['approved', 'rejected'];

const INCIDENT_KEY_PREFIX = 'incident';
const EVIDENCE_HASH_KEY_PREFIX = 'evidenceHash';

function requireNonEmpty(value, fieldName) {
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new Error(`${fieldName} must be a non-empty string`);
    }
    return value;
}

function requireEnum(value, allowed, fieldName) {
    requireNonEmpty(value, fieldName);
    if (!allowed.includes(value)) {
        throw new Error(
            `${fieldName} must be one of [${allowed.join(', ')}], got '${value}'`
        );
    }
    return value;
}

function requireIsoTimestamp(value, fieldName) {
    requireNonEmpty(value, fieldName);
    if (Number.isNaN(Date.parse(value))) {
        throw new Error(`${fieldName} must be an ISO-8601 timestamp, got '${value}'`);
    }
    return value;
}

function requireBoolString(value, fieldName) {
    requireNonEmpty(value, fieldName);
    const normalized = value.toLowerCase();
    if (normalized !== 'true' && normalized !== 'false') {
        throw new Error(`${fieldName} must be 'true' or 'false', got '${value}'`);
    }
    return normalized === 'true';
}

function incidentKey(incidentId) {
    return `${INCIDENT_KEY_PREFIX}:${incidentId}`;
}

function evidenceHashKey(hash) {
    return `${EVIDENCE_HASH_KEY_PREFIX}:${hash}`;
}

/**
 * Provenance ledger for the Patient-Aware Cyber Resilience platform
 * (architecture spec Section 14). Implements the six chaincode operations
 * from the brief, unchanged as names: recordIncident, recordDecision,
 * recordApproval, recordResponse, recordRecovery, verifyEvidence.
 *
 * Design decisions made here, beyond the brief's bare function signatures
 * (documented so they read as decisions, not as literal spec text):
 *
 * - recordIncident is write-once per incident_id. Re-recording the same
 *   incident_id is rejected rather than silently overwritten -- the whole
 *   point of a provenance ledger is that the initial record of an incident
 *   can't quietly change after the fact.
 * - recordDecision / recordApproval / recordResponse / recordRecovery are
 *   append-only per incident: an incident can legitimately be
 *   re-risk-assessed, re-approved, re-responded-to, and re-verified
 *   multiple times over its lifecycle (this matches the agent/policy/
 *   recovery loop built in Phases 4-7), so each call adds a new timestamped
 *   entry rather than overwriting the previous one. Each requires the
 *   incident to already exist (recordIncident first), so the chain of
 *   custody can't start mid-lifecycle.
 * - verifyEvidence checks a hash against an index populated by BOTH
 *   recordIncident's evidence_hash AND recordRecovery's
 *   residual_threats_hash (when present) -- any hash this contract has
 *   ever committed as evidence, not only the initial incident hash. The
 *   brief's one-line comment ("checks a hash against what's on-chain")
 *   doesn't specify this scope; this is this project's own extension,
 *   flagged here rather than presented as literal spec text.
 * - getIncident / getProvenanceTrail are read-only convenience functions
 *   beyond the six named operations, added for test and audit-dashboard
 *   use. The six-operation list is unchanged; these are additions, not a
 *   reinterpretation of it.
 */
class ProvenanceContract extends Contract {
    async recordIncident(ctx, incidentId, deviceId, attackType, evidenceHash, timestamp) {
        requireNonEmpty(incidentId, 'incident_id');
        requireNonEmpty(deviceId, 'device_id');
        requireNonEmpty(attackType, 'attack_type');
        requireNonEmpty(evidenceHash, 'evidence_hash');
        requireIsoTimestamp(timestamp, 'timestamp');

        const key = incidentKey(incidentId);
        const existing = await ctx.stub.getState(key);
        if (existing && existing.length > 0) {
            throw new Error(
                `incident '${incidentId}' already has a recordIncident entry -- ` +
                'the initial incident record cannot be overwritten'
            );
        }

        const record = {
            incidentId,
            deviceId,
            attackType,
            evidenceHash,
            timestamp,
            recordedTxId: ctx.stub.getTxID(),
        };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));
        await ctx.stub.putState(
            evidenceHashKey(evidenceHash),
            Buffer.from(JSON.stringify({ incidentId, source: 'recordIncident', recordedTxId: record.recordedTxId }))
        );
        return JSON.stringify(record);
    }

    async recordDecision(ctx, incidentId, riskScoreHash, policyRuleId, recommendedAction) {
        requireNonEmpty(incidentId, 'incident_id');
        requireNonEmpty(riskScoreHash, 'risk_score_hash');
        requireNonEmpty(policyRuleId, 'policy_rule_id');
        requireEnum(recommendedAction, RESPONSE_ACTION_CATEGORIES, 'recommended_action');

        await requireIncidentExists(ctx, incidentId);

        const record = {
            incidentId,
            riskScoreHash,
            policyRuleId,
            recommendedAction,
            recordedTxId: ctx.stub.getTxID(),
        };
        const key = ctx.stub.createCompositeKey('decision', [incidentId, ctx.stub.getTxID()]);
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));
        return JSON.stringify(record);
    }

    async recordApproval(ctx, incidentId, approverIdentity, decision, timestamp) {
        requireNonEmpty(incidentId, 'incident_id');
        requireNonEmpty(approverIdentity, 'approver_identity');
        requireEnum(decision, APPROVAL_DECISIONS, 'decision');
        requireIsoTimestamp(timestamp, 'timestamp');

        await requireIncidentExists(ctx, incidentId);

        const record = {
            incidentId,
            approverIdentity,
            decision,
            timestamp,
            recordedTxId: ctx.stub.getTxID(),
        };
        const key = ctx.stub.createCompositeKey('approval', [incidentId, ctx.stub.getTxID()]);
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));
        return JSON.stringify(record);
    }

    async recordResponse(ctx, incidentId, actionTaken, executedBy, timestamp) {
        requireNonEmpty(incidentId, 'incident_id');
        requireEnum(actionTaken, RESPONSE_ACTION_CATEGORIES, 'action_taken');
        requireNonEmpty(executedBy, 'executed_by');
        requireIsoTimestamp(timestamp, 'timestamp');

        await requireIncidentExists(ctx, incidentId);

        const record = {
            incidentId,
            actionTaken,
            executedBy,
            timestamp,
            recordedTxId: ctx.stub.getTxID(),
        };
        const key = ctx.stub.createCompositeKey('response', [incidentId, ctx.stub.getTxID()]);
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));
        return JSON.stringify(record);
    }

    async recordRecovery(ctx, incidentId, recoveryVerified, residualThreatsHash) {
        requireNonEmpty(incidentId, 'incident_id');
        const verified = requireBoolString(recoveryVerified, 'recovery_verified');

        // residual_threats_hash is nullable in the off-chain schema
        // (RecoveryProvenance.residual_threats_hash: str | None). Chaincode
        // args are always strings, so an empty string is this contract's
        // convention for "not provided" -- documented here since Fabric
        // itself has no native null for a string arg.
        const hasResidualHash = typeof residualThreatsHash === 'string' && residualThreatsHash.trim().length > 0;

        await requireIncidentExists(ctx, incidentId);

        const record = {
            incidentId,
            recoveryVerified: verified,
            residualThreatsHash: hasResidualHash ? residualThreatsHash : null,
            recordedTxId: ctx.stub.getTxID(),
        };
        const key = ctx.stub.createCompositeKey('recovery', [incidentId, ctx.stub.getTxID()]);
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));

        if (hasResidualHash) {
            await ctx.stub.putState(
                evidenceHashKey(residualThreatsHash),
                Buffer.from(JSON.stringify({ incidentId, source: 'recordRecovery', recordedTxId: record.recordedTxId }))
            );
        }
        return JSON.stringify(record);
    }

    async verifyEvidence(ctx, evidenceHash) {
        requireNonEmpty(evidenceHash, 'evidence_hash');
        const existing = await ctx.stub.getState(evidenceHashKey(evidenceHash));
        return existing && existing.length > 0;
    }

    // --- Read-only convenience extensions (not part of the six-operation
    // list above; see class docstring). ---

    async getIncident(ctx, incidentId) {
        requireNonEmpty(incidentId, 'incident_id');
        const data = await ctx.stub.getState(incidentKey(incidentId));
        if (!data || data.length === 0) {
            throw new Error(`no incident recorded with incident_id '${incidentId}'`);
        }
        return data.toString('utf8');
    }

    async getProvenanceTrail(ctx, incidentId) {
        requireNonEmpty(incidentId, 'incident_id');
        const trail = { decisions: [], approvals: [], responses: [], recoveries: [] };
        const sections = [
            ['decision', 'decisions'],
            ['approval', 'approvals'],
            ['response', 'responses'],
            ['recovery', 'recoveries'],
        ];
        for (const [objectType, trailKey] of sections) {
            const iterator = await ctx.stub.getStateByPartialCompositeKey(objectType, [incidentId]);
            let result = await iterator.next();
            while (!result.done) {
                trail[trailKey].push(JSON.parse(result.value.value.toString('utf8')));
                result = await iterator.next();
            }
            await iterator.close();
        }
        return JSON.stringify(trail);
    }

}

// Module-level helper, not a class method -- fabric-contract-api discovers
// transactions by introspecting the contract class's own prototype methods,
// so keeping this off the class avoids it ever being (even accidentally)
// exposed as an invokable transaction.
async function requireIncidentExists(ctx, incidentId) {
    const data = await ctx.stub.getState(incidentKey(incidentId));
    if (!data || data.length === 0) {
        throw new Error(
            `incident '${incidentId}' has no recordIncident entry -- ` +
            'call recordIncident before recording a decision, approval, response, or recovery'
        );
    }
}

module.exports = ProvenanceContract;
module.exports.RESPONSE_ACTION_CATEGORIES = RESPONSE_ACTION_CATEGORIES;
module.exports.APPROVAL_DECISIONS = APPROVAL_DECISIONS;
