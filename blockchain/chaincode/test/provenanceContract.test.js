'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const ProvenanceContract = require('../lib/provenanceContract');
const { FakeContext } = require('./fakeContext');

const ISO_TS = '2026-10-12T00:00:00.000Z';

function newFixture() {
    return { contract: new ProvenanceContract(), ctx: new FakeContext() };
}

async function recordSampleIncident(contract, ctx, overrides = {}) {
    const args = {
        incidentId: 'INC-1',
        deviceId: 'dev-infusion-pump-01',
        attackType: 'ddos',
        evidenceHash: 'hash-evidence-abc',
        timestamp: ISO_TS,
        ...overrides,
    };
    await contract.recordIncident(
        ctx, args.incidentId, args.deviceId, args.attackType, args.evidenceHash, args.timestamp
    );
    return args;
}

test('recordIncident stores a retrievable record', async () => {
    const { contract, ctx } = newFixture();
    await recordSampleIncident(contract, ctx);

    const stored = JSON.parse(await contract.getIncident(ctx, 'INC-1'));
    assert.equal(stored.incidentId, 'INC-1');
    assert.equal(stored.deviceId, 'dev-infusion-pump-01');
    assert.equal(stored.attackType, 'ddos');
    assert.equal(stored.evidenceHash, 'hash-evidence-abc');
    assert.equal(stored.timestamp, ISO_TS);
    assert.ok(stored.recordedTxId);
});

test('recordIncident rejects re-recording the same incident_id', async () => {
    const { contract, ctx } = newFixture();
    await recordSampleIncident(contract, ctx);

    await assert.rejects(
        () => recordSampleIncident(contract, ctx, { evidenceHash: 'a-different-hash' }),
        /already has a recordIncident entry/
    );
});

test('recordIncident rejects a non-ISO timestamp', async () => {
    const { contract, ctx } = newFixture();
    await assert.rejects(
        () => recordSampleIncident(contract, ctx, { timestamp: 'not-a-timestamp' }),
        /ISO-8601 timestamp/
    );
});

test('recordIncident rejects an empty required field', async () => {
    const { contract, ctx } = newFixture();
    await assert.rejects(
        () => recordSampleIncident(contract, ctx, { deviceId: '' }),
        /device_id must be a non-empty string/
    );
});

test('recordDecision requires the incident to already exist', async () => {
    const { contract, ctx } = newFixture();
    await assert.rejects(
        () => contract.recordDecision(ctx, 'INC-UNKNOWN', 'hash-risk', 'RULE-1', 'isolate_critical'),
        /has no recordIncident entry/
    );
});

test('recordDecision validates recommended_action against the known category list', async () => {
    const { contract, ctx } = newFixture();
    await recordSampleIncident(contract, ctx);

    await assert.rejects(
        () => contract.recordDecision(ctx, 'INC-1', 'hash-risk', 'RULE-1', 'not_a_real_action'),
        /recommended_action must be one of/
    );

    const result = JSON.parse(
        await contract.recordDecision(ctx, 'INC-1', 'hash-risk', 'RULE-1', 'isolate_critical')
    );
    assert.equal(result.incidentId, 'INC-1');
    assert.equal(result.riskScoreHash, 'hash-risk');
    assert.equal(result.policyRuleId, 'RULE-1');
    assert.equal(result.recommendedAction, 'isolate_critical');
});

test('recordApproval validates decision against approved/rejected only', async () => {
    const { contract, ctx } = newFixture();
    await recordSampleIncident(contract, ctx);

    await assert.rejects(
        () => contract.recordApproval(ctx, 'INC-1', 'soc-analyst-1', 'maybe', ISO_TS),
        /decision must be one of/
    );

    const result = JSON.parse(
        await contract.recordApproval(ctx, 'INC-1', 'soc-analyst-1', 'approved', ISO_TS)
    );
    assert.equal(result.approverIdentity, 'soc-analyst-1');
    assert.equal(result.decision, 'approved');
});

test('recordResponse validates action_taken and requires an existing incident', async () => {
    const { contract, ctx } = newFixture();

    await assert.rejects(
        () => contract.recordResponse(ctx, 'INC-1', 'isolate_critical', 'orchestrator', ISO_TS),
        /has no recordIncident entry/
    );

    await recordSampleIncident(contract, ctx);
    await assert.rejects(
        () => contract.recordResponse(ctx, 'INC-1', 'not_a_real_action', 'orchestrator', ISO_TS),
        /action_taken must be one of/
    );

    const result = JSON.parse(
        await contract.recordResponse(ctx, 'INC-1', 'isolate_critical', 'orchestrator', ISO_TS)
    );
    assert.equal(result.actionTaken, 'isolate_critical');
    assert.equal(result.executedBy, 'orchestrator');
});

test('recordRecovery parses recovery_verified strictly and treats empty residual_threats_hash as absent', async () => {
    const { contract, ctx } = newFixture();
    await recordSampleIncident(contract, ctx);

    await assert.rejects(
        () => contract.recordRecovery(ctx, 'INC-1', 'not-a-bool', ''),
        /recovery_verified must be 'true' or 'false'/
    );

    const result = JSON.parse(await contract.recordRecovery(ctx, 'INC-1', 'true', ''));
    assert.equal(result.recoveryVerified, true);
    assert.equal(result.residualThreatsHash, null);
});

test('recordRecovery with a residual_threats_hash makes it verifiable via verifyEvidence', async () => {
    const { contract, ctx } = newFixture();
    await recordSampleIncident(contract, ctx);

    assert.equal(await contract.verifyEvidence(ctx, 'residual-hash-xyz'), false);

    await contract.recordRecovery(ctx, 'INC-1', 'false', 'residual-hash-xyz');

    assert.equal(await contract.verifyEvidence(ctx, 'residual-hash-xyz'), true);
});

test('verifyEvidence is true for a recorded incident evidence_hash and false for an unknown one', async () => {
    const { contract, ctx } = newFixture();
    const args = await recordSampleIncident(contract, ctx);

    assert.equal(await contract.verifyEvidence(ctx, args.evidenceHash), true);
    assert.equal(await contract.verifyEvidence(ctx, 'never-recorded-hash'), false);
});

test('getIncident throws for an unknown incident_id', async () => {
    const { contract, ctx } = newFixture();
    await assert.rejects(
        () => contract.getIncident(ctx, 'NOPE'),
        /no incident recorded/
    );
});

test('getProvenanceTrail accumulates every decision/approval/response/recovery for an incident, in order, without leaking across incidents', async () => {
    const { contract, ctx } = newFixture();
    await recordSampleIncident(contract, ctx, { incidentId: 'INC-1' });
    // INC-10 is a genuine edge case, not just a different ID: without a
    // delimiter after each composite-key attribute, the string prefix
    // "INC-1" would also match "INC-10", leaking INC-10's events into
    // INC-1's trail. createCompositeKey terminates every attribute with a
    // NUL, so "INC-1\0" is not a prefix of "INC-10\0...".
    await recordSampleIncident(contract, ctx, { incidentId: 'INC-10', evidenceHash: 'hash-for-inc-10' });

    await contract.recordDecision(ctx, 'INC-1', 'hash-risk-1', 'RULE-1', 'isolate_critical');
    await contract.recordDecision(ctx, 'INC-1', 'hash-risk-2', 'RULE-2', 'shutdown');
    await contract.recordApproval(ctx, 'INC-1', 'soc-analyst-1', 'approved', ISO_TS);
    await contract.recordResponse(ctx, 'INC-1', 'shutdown', 'orchestrator', ISO_TS);
    await contract.recordRecovery(ctx, 'INC-1', 'true', '');

    // A decision recorded against the OTHER incident must not show up in
    // INC-1's trail.
    await contract.recordDecision(ctx, 'INC-10', 'hash-risk-other', 'RULE-9', 'block_traffic');

    const trail = JSON.parse(await contract.getProvenanceTrail(ctx, 'INC-1'));
    assert.equal(trail.decisions.length, 2);
    assert.equal(trail.approvals.length, 1);
    assert.equal(trail.responses.length, 1);
    assert.equal(trail.recoveries.length, 1);
    assert.ok(trail.decisions.every((d) => d.incidentId === 'INC-1'));

    const otherTrail = JSON.parse(await contract.getProvenanceTrail(ctx, 'INC-10'));
    assert.equal(otherTrail.decisions.length, 1);
    assert.equal(otherTrail.decisions[0].policyRuleId, 'RULE-9');
});
