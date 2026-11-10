// The same Python-generated synthetic packages run in Node and in a real browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import * as verifier from '../docs/verifier.mjs';

const location = './fixtures/synthetic/browser-vectors.json';
const fixtures = JSON.parse(await readFile(new URL(location, import.meta.url), 'utf8'));
assert.equal(fixtures.mode, 'SYNTHETIC');
assert.equal(fixtures.schema_version, 'meshdraw-browser-vectors-v1');
for (const vector of fixtures.vectors) {
  test(vector.name, async () => {
    const result = await verifier.verifyPackage(vector.package);
    assert.equal(result.status, 'MATCH');
    assert.equal(result.provenance, 'NOT_INDEPENDENTLY_CONFIRMED');
    assert.deepEqual(result.selection, vector.package.expected.selection);
    assert.deepEqual(result.calculation, vector.package.expected.calculation);
  });
}
for (const vector of fixtures.mapping_vectors) {
  test(vector.name, async () => {
    assert.deepEqual(await verifier.mapDigest(vector.root_hex, vector.tickets, vector.max_words), vector.expected);
  });
}

test('changed RF input is rejected before a match can be claimed', async () => {
  const changed = structuredClone(fixtures.vectors[0].package);
  const observation = changed.snapshot.rows.find(row => row.layer === 'observation');
  observation.fields.rssi.value = '-123.25';
  await assert.rejects(verifier.verifyPackage(changed));
});

test('a changed declared winner is not used as the computed answer', async () => {
  const changed = structuredClone(fixtures.vectors[0].package);
  changed.expected.calculation.mapping.ticket = '99999999';
  changed.manifest.expected = await verifier.digest(changed.expected);
  await assert.rejects(verifier.verifyPackage(changed), /CALCULATION_MISMATCH/);
});

test('JSON parser rejects duplicate keys and unsafe numeric literals', () => {
  assert.throws(() => verifier.parsePackageText('{"a":1,"a":2}'));
  assert.throws(() => verifier.parsePackageText('{"id":9007199254740993}'));
});
