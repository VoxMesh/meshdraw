/* archive-input-v1 / archive-profile-implementation-1.0.1.
 * Exact, local arithmetic on the supplied package. No network, random values,
 * source authentication, entropy claim, or independent time/provenance proof.
 * Python reference: meshdraw_public/archive/{math,profile}.py and core.map_digest.
 */

export const ALGORITHM_VERSION = 'archive-profile-implementation-1.0.1';
export const UI_CONTRACT = 'meshdraw-web-v3';
const encoder = new TextEncoder();
const PREFIX = encoder.encode('MeshDraw-archive-input-v1/DEDUP_HASH\0');
const MAP_PREFIX = encoder.encode('MeshDraw-core-map-v0.2\0');
const DECIMAL = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,2})?(?![\s\S])/;
const INTEGER = /^-?(?:0|[1-9][0-9]*)(?![\s\S])/;
const FIELDS = new Set(['id', 'packet_id', 'transmission_id', 'observation_id',
  'observer_id', 'observer_iata', 'observation_count', 'hash', 'timestamp',
  'received_at', 'receivedAt', 'source_time', 'source_epoch_s', 'time',
  'observed_at', 'rx_time', 'direction', 'region', 'iata', 'first_seen',
  'last_seen', 'created_at', 'updated_at', 'server_timestamp', 'rssi', 'snr']);
const ROW_FIELDS = ['layer', 'parent_key', 'fields', 'request_utc', 'page', 'ordinal'];
const POLICY_FIELDS = ['profile', 'candidate', 'direction', 'region', 'grouping', 'representative',
  'pair_order', 'quantization', 'rf_abs_limit', 'min_rows', 'min_observers', 'mapping_max_words',
  'source_snapshot_sha256', 'input_document_sha256_before_calculation', 'start', 'end', 'tickets',
  'physical_source_time', 'physical_receive_time', 'retained', 'rf_prefix_hex', 'mapping'];
const FIXED_POLICY = {
  profile: 'archive-input-v1', candidate: 'DEDUP_HASH',
  grouping: 'typed-observer-id-and-parent-transmission-key',
  representative: 'earliest-archive-us-then-typed-observation-id',
  pair_order: 'archive-us-observer-parent-observation-id',
  quantization: 'quarter-half-even', rf_prefix_hex: toHex(PREFIX),
  direction: 'rx', region: 'all', retained: 'unknown-not-provided',
  physical_source_time: 'unknown', physical_receive_time: 'unknown',
  mapping: 'v0.2-map_digest-rejection-sampling', mapping_max_words: 8,
  min_rows: 8, min_observers: 2, rf_abs_limit: '1000000',
};

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function fields(value, names, code) {
  if (!object(value) || Object.keys(value).length !== names.length
      || names.some(name => !Object.hasOwn(value, name))) fail(code);
}
function integer(value, low, high, code = 'INTEGER_BOUND') {
  if (!Number.isSafeInteger(value) || value < low || value > high) fail(code);
}
function ascii(text) { return typeof text === 'string' && /^[\x00-\x7f]*$/.test(text); }
function requireAsciiTree(value) {
  if (typeof value === 'string') { if (!ascii(value)) fail('NON_ASCII_JSON'); }
  else if (Array.isArray(value)) value.forEach(requireAsciiTree);
  else if (object(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (!ascii(key)) fail('NON_ASCII_JSON');
      requireAsciiTree(child);
    }
  }
}

// Python compares strings by Unicode code point, not locale or UTF-16 units.
function compare(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const order = compare(a[i], b[i]); if (order) return order;
    }
    return a.length < b.length ? -1 : a.length > b.length ? 1 : 0;
  }
  if (typeof a === 'string' && typeof b === 'string') {
    const left = Array.from(a, c => c.codePointAt(0)), right = Array.from(b, c => c.codePointAt(0));
    return compare(left, right);
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

// Python json.dumps(ensure_ascii=True, sort_keys=True, separators=(',', ':')).
export function canonicalJson(value) {
  let nodes = 0;
  const active = new Set();
  function quote(text) {
    return JSON.stringify(text).replace(/[\u007f-\uffff]/g,
      c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  }
  function visit(item, depth) {
    if (++nodes > 200000 || depth > 32) fail('JSON_STRUCTURE_LIMIT');
    if (item === null) return 'null';
    if (typeof item === 'boolean') return item ? 'true' : 'false';
    if (typeof item === 'string') return quote(item);
    if (typeof item === 'number') {
      if (!Number.isSafeInteger(item)) fail('UNSAFE_JSON_INTEGER');
      return String(item);
    }
    if (!Array.isArray(item) && !object(item)) fail('INVALID_JSON_TYPE');
    if (active.has(item)) fail('JSON_CYCLE');
    active.add(item);
    const result = Array.isArray(item)
      ? '[' + Array.from(item, child => visit(child, depth + 1)).join(',') + ']'
      : '{' + Object.keys(item).sort(compare).map(key => {
        if (++nodes > 200000) fail('JSON_STRUCTURE_LIMIT');
        return quote(key) + ':' + visit(item[key], depth + 1);
      }).join(',') + '}';
    active.delete(item);
    return result;
  }
  const result = visit(value, 0);
  if (result.length > 16 * 1024 * 1024) fail('JSON_TOO_LARGE');
  return result;
}

// Strict parser: never lose precision or silently overwrite duplicate keys.
export function parsePackageText(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > 4 * 1024 * 1024) fail('PACKAGE_BYTE_LIMIT');
  let index = 0, nodes = 0;
  function space() { while (/[\x20\t\r\n]/.test(text[index] ?? '\0')) index++; }
  function string() {
    const begin = index++;
    while (index < text.length) {
      const char = text[index++];
      if (char === '"') {
        try { return JSON.parse(text.slice(begin, index)); } catch { fail('INVALID_JSON_STRING'); }
      }
      if (char === '\\') index++;
      else if (char.charCodeAt(0) < 32) fail('INVALID_JSON_STRING');
    }
    fail('INVALID_JSON_STRING');
  }
  function value(depth) {
    if (++nodes > 200000 || depth > 32) fail('JSON_STRUCTURE_LIMIT');
    space(); const char = text[index];
    if (char === '"') return string();
    if (char === '{') {
      index++; space(); const out = Object.create(null);
      if (text[index] === '}') { index++; return out; }
      while (true) {
        space(); if (text[index] !== '"') fail('INVALID_JSON');
        const key = string(); space();
        if (Object.hasOwn(out, key)) fail('DUPLICATE_JSON_KEY');
        if (text[index++] !== ':') fail('INVALID_JSON');
        out[key] = value(depth + 1); space();
        if (text[index] === '}') { index++; return out; }
        if (text[index++] !== ',') fail('INVALID_JSON');
      }
    }
    if (char === '[') {
      index++; space(); const out = [];
      if (text[index] === ']') { index++; return out; }
      while (true) {
        out.push(value(depth + 1)); space();
        if (text[index] === ']') { index++; return out; }
        if (text[index++] !== ',') fail('INVALID_JSON');
      }
    }
    for (const [literal, decoded] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, index)) { index += literal.length; return decoded; }
    }
    const match = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)/);
    if (!match) fail('INVALID_JSON');
    index += match[0].length;
    if (/[.eE]/.test(text[index] ?? '\0')) fail('NON_INTEGER_JSON_NUMBER');
    const decoded = Number(match[0]);
    if (!Number.isSafeInteger(decoded)) fail('UNSAFE_JSON_INTEGER');
    return decoded;
  }
  const result = value(0); space();
  if (index !== text.length) fail('INVALID_JSON');
  return result;
}

export async function sha256(value) {
  if (!globalThis.crypto?.subtle) fail('WEBCRYPTO_UNAVAILABLE');
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  if (!(bytes instanceof Uint8Array)) fail('EXPECTED_BYTES');
  return toHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)));
}
export async function digest(value) { return sha256(canonicalJson(value)); }
function toHex(bytes) { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
function fromHex(text) {
  if (typeof text !== 'string' || text.length % 2 || !/^[0-9a-f]*(?![\s\S])/.test(text)) fail('INVALID_HEX');
  return Uint8Array.from(text.match(/../g) ?? [], pair => parseInt(pair, 16));
}
function join(...arrays) {
  const out = new Uint8Array(arrays.reduce((length, part) => length + part.length, 0));
  let at = 0; for (const part of arrays) { out.set(part, at); at += part.length; } return out;
}
function u32(value) {
  integer(value, 0, 0xffffffff); const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false); return out;
}

function gcd(a, b) { a = a < 0n ? -a : a; while (b) [a, b] = [b, a % b]; return a; }
export function exact(text) {
  if (typeof text !== 'string' || text.length > 128 || !DECIMAL.test(text)) fail('BAD_RF_NUMBER');
  const match = text.match(/^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?(?![\s\S])/);
  const fraction = match[3] ?? '', exponent = Number(match[4] ?? 0) - fraction.length;
  let n = BigInt(match[2] + fraction) * (match[1] ? -1n : 1n), d = 1n;
  if (exponent >= 0) n *= 10n ** BigInt(exponent); else d = 10n ** BigInt(-exponent);
  const common = gcd(n, d); return [n / common, d / common];
}
function plain([n, d]) {
  if (d === 1n) return n.toString();
  let scale = 0, power = 1n;
  while (scale <= 128 && power % d !== 0n) { scale++; power *= 10n; }
  if (scale > 128) fail('DECIMAL_SCALE_LIMIT');
  const digits = ((n < 0n ? -n : n) * power / d).toString().padStart(scale + 1, '0');
  return ((n < 0n ? '-' : '') + digits.slice(0, -scale) + '.' + digits.slice(-scale)).replace(/0+$/, '').replace(/\.$/, '');
}
export function quarter(text) {
  let [n, d] = exact(text); n *= 4n;
  const sign = n < 0n ? -1n : 1n, magnitude = n < 0n ? -n : n;
  let quotient = magnitude / d; const twice = magnitude % d * 2n;
  if (twice > d || twice === d && quotient % 2n === 1n) quotient++;
  return quotient * sign;
}

export function toUtcUs(value) {
  if (typeof value !== 'string' || value.length > 256) fail('INVALID_TIME');
  const m = value.match(/^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})(?![\s\S])/);
  if (!m) fail('INVALID_TIME');
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  const fraction = m[7] ?? '', zone = m[8];
  if (/[1-9]/.test(fraction.slice(6))) fail('UNSUPPORTED_PRECISION');
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const months = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > months[month - 1]
      || hour > 23 || minute > 59 || second > 59) fail('INVALID_TIME');
  let offset = 0;
  if (zone !== 'Z') {
    const h = Number(zone.slice(1, 3)), minutes = Number(zone.slice(4));
    if (h > 23 || minutes > 59) fail('INVALID_TIME');
    offset = (h * 60 + minutes) * (zone[0] === '-' ? -1 : 1);
  }
  // Gregorian civil date -> days since 1970. All calendar work is small integers;
  // only BigInt forms seconds/microseconds, including years outside Number-us.
  const adjustedYear = year - (month <= 2 ? 1 : 0), era = Math.floor(adjustedYear / 400);
  const yoe = adjustedYear - era * 400;
  const doy = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1;
  const days = era * 146097 + yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy - 719468;
  const result = (BigInt(days) * 86400n + BigInt(hour * 3600 + minute * 60 + second - offset * 60)) * 1000000n
    + BigInt((fraction.slice(0, 6) + '000000').slice(0, 6));
  if (result < -(2n ** 63n) || result > 2n ** 63n - 1n) fail('TIME_RANGE');
  return result;
}

function validateTickets(tickets) {
  if (!Array.isArray(tickets) || tickets.length < 2 || tickets.length > 10000) fail('TICKET_COUNT');
  const seen = new Set();
  for (const ticket of tickets) {
    if (typeof ticket !== 'string' || !/^[0-9]{1,32}(?![\s\S])/.test(ticket)) fail('INVALID_TICKET');
    const key = BigInt(ticket).toString(); if (seen.has(key)) fail('DUPLICATE_TICKET'); seen.add(key);
  }
}
export async function mapDigest(root, tickets, maxWords = 8) {
  if (typeof root === 'string') root = fromHex(root);
  if (!(root instanceof Uint8Array) || root.length !== 32) fail('INVALID_DIGEST');
  validateTickets(tickets); integer(maxWords, 1, 1024, 'MAPPING_MAX_WORDS');
  const count = BigInt(tickets.length), limit = 2n ** 256n / count * count;
  for (let index = 0; index < maxWords; index++) {
    const bytes = index === 0 ? root : fromHex(await sha256(join(MAP_PREFIX, root, u32(index))));
    const word = BigInt('0x' + toHex(bytes));
    if (word < limit) {
      const selected = Number(word % count);
      return {index: selected, ticket: tickets[selected], words_used: index + 1};
    }
  }
  return {index: null, ticket: null, words_used: maxWords};
}

function token(field) {
  fields(field, ['kind', 'value'], 'TYPED_VALUE_REQUIRED');
  if (!['string', 'integer', 'number', 'boolean', 'null'].includes(field.kind)) fail('UNKNOWN_VALUE_KIND');
  if (field.kind === 'null') { if (field.value !== null) fail('BAD_NULL'); }
  else if (field.kind === 'boolean') { if (typeof field.value !== 'boolean') fail('BAD_BOOLEAN'); }
  else if (typeof field.value !== 'string' || field.value.length > 512) fail('TECHNICAL_VALUE_LIMIT');
  return [field.kind, field.value === null ? 'None' : field.value === true ? 'True' : field.value === false ? 'False' : field.value];
}
function value(row, key) { return row.fields[key]?.value ?? null; }
function stableId(row) { return token(row.fields.id); }
function typed(field) {
  token(field);
  if (field.kind === 'integer' && (field.value.length > 32 || !INTEGER.test(field.value))) fail('TYPED_INTEGER');
  if (field.kind === 'number' && (field.value.length > 128 || !DECIMAL.test(field.value))) fail('TYPED_NUMBER');
}
function parentKey(row) {
  for (const key of ['id', 'packet_id', 'hash']) {
    const field = row.fields[key];
    if (field && field.kind !== 'null') {
      // Python's json.dumps default separators are intentionally spaced here.
      return key + ':{"kind": ' + canonicalJson(field.kind) + ', "value": ' + canonicalJson(field.value) + '}';
    }
  }
  return null;
}

export function checkSnapshot(snapshot) {
  fields(snapshot, ['schema_version', 'complete', 'reported_total', 'rows', 'request_offsets'], 'SNAPSHOT_FIELDS');
  if (snapshot.schema_version !== 'meshdraw-source-snapshot-v1' || snapshot.complete !== true) fail('INCOMPLETE_SNAPSHOT');
  integer(snapshot.reported_total, 0, 200);
  const offsets = snapshot.request_offsets;
  if (!Array.isArray(offsets) || offsets.length < 1 || offsets.length > 4) fail('PAGE_METADATA');
  offsets.forEach(offset => integer(offset, 0, 200));
  if (new Set(offsets).size !== offsets.length) fail('DUPLICATE_OFFSET');
  if (!Array.isArray(snapshot.rows) || snapshot.rows.length > 3000) fail('RECORD_LIMIT');
  const seen = new Set(), parents = new Map(), children = [];
  for (const row of snapshot.rows) {
    fields(row, ROW_FIELDS, 'RECORD_FIELDS');
    if (!['packet', 'observation'].includes(row.layer) || !object(row.fields)
        || Object.keys(row.fields).some(key => !FIELDS.has(key))) fail('RECORD_STRUCTURE');
    integer(row.page, 0, 3); integer(row.ordinal, 0, 4096);
    if (typeof row.request_utc !== 'string' || row.request_utc.length > 128) fail('DOWNLOAD_METADATA');
    for (const [key, field] of Object.entries(row.fields)) {
      typed(field);
      if (['rssi', 'snr'].includes(key) && field.kind !== 'null'
          && (!['integer', 'number', 'string'].includes(field.kind) || field.value.length > 128 || !DECIMAL.test(field.value))) fail('RF_NUMBER');
    }
    const id = row.fields.id;
    if (!id || !['integer', 'string'].includes(id.kind) || !id.value || id.value.length > 128) fail('RECORD_ID');
    const key = canonicalJson([row.layer, id.kind, id.value]);
    if (seen.has(key)) fail('DUPLICATE_LOCAL_ID'); seen.add(key);
    if (row.layer === 'packet') {
      if (row.parent_key !== null) fail('TOP_PARENT_LINK');
      const parent = parentKey(row);
      if (!parent || parents.has(parent)) fail('DUPLICATE_PARENT_KEY'); parents.set(parent, row);
    } else {
      if (typeof row.parent_key !== 'string' || row.parent_key.length > 1024) fail('CHILD_PARENT_LINK');
      children.push(row);
    }
  }
  if (children.some(row => !parents.has(row.parent_key))) fail('ORPHAN_OBSERVATION');
  for (const [key, parent] of parents) {
    const declared = parent.fields.observation_count;
    if (!declared || declared.kind !== 'integer' || !INTEGER.test(declared.value)) fail('MISSING_CHILD_COUNT');
    if (BigInt(declared.value) !== BigInt(children.filter(row => row.parent_key === key).length)) fail('INCOMPLETE_CHILDREN');
  }
  if (parents.size !== snapshot.reported_total) fail('INCOMPLETE_PARENT_TOTAL');
  let expected = 0;
  for (const [page, offset] of [...offsets].sort((a, b) => a - b).entries()) {
    if (offset !== expected) fail('PAGE_OFFSET_GAP');
    const count = [...parents.values()].filter(row => row.page === page).length;
    if (count !== Math.min(100, snapshot.reported_total - offset)) fail('SHORT_STUDY_PAGE');
    if (count > 100 || count === 0 && snapshot.reported_total > 0) fail('PAGE_PARENT_COUNT');
    expected += count;
  }
  if (expected !== snapshot.reported_total || snapshot.rows.some(row => row.page >= offsets.length)) fail('PAGE_RECORDS_MISSING');
  if (children.some(row => row.page !== parents.get(row.parent_key).page)) fail('CHILD_PAGE_LINK');
  return {parents, children};
}

export function windowFilter(plan, snapshot) {
  const start = toUtcUs(plan.source.query.since), end = toUtcUs(plan.source.query.until);
  const parents = new Map(); let excludedParents = 0, excludedChildren = 0, unknownParentTimes = 0, unknownChildTimes = 0;
  for (const row of snapshot.rows) {
    if (row.layer !== 'packet') continue;
    let stamp;
    try { stamp = toUtcUs(value(row, 'first_seen')); }
    catch { unknownParentTimes++; excludedParents++; continue; }
    if (start <= stamp && stamp < end) parents.set(parentKey(row), row); else excludedParents++;
  }
  const children = [];
  for (const row of snapshot.rows) {
    if (row.layer !== 'observation') continue;
    if (!parents.has(row.parent_key)) { excludedChildren++; continue; }
    let stamp;
    try { stamp = toUtcUs(value(row, 'timestamp')); }
    catch { unknownChildTimes++; excludedChildren++; continue; }
    if (start <= stamp && stamp < end) children.push(row); else excludedChildren++;
  }
  return {rows: children, selection: {policy: 'archive-window-study-v1',
    eligible_parents: parents.size, eligible_children: children.length,
    excluded_parents: excludedParents, excluded_children: excludedChildren,
    unknown_parent_times: unknownParentTimes, unknown_child_times: unknownChildTimes,
    scope: 'Deletes returned out-of-window records only; never recovers server omissions'}};
}

function validatePolicy(policy) {
  if (!object(policy)) fail('POLICY_REQUIRED');
  for (const [key, expected] of Object.entries(FIXED_POLICY)) if (policy[key] !== expected) fail('UNSUPPORTED_POLICY_' + key);
  const start = toUtcUs(policy.start), end = toUtcUs(policy.end);
  if (start >= end) fail('BAD_WINDOW'); validateTickets(policy.tickets);
}

export async function evaluateArchive(policy, input) {
  canonicalJson(policy); canonicalJson(input); requireAsciiTree(policy); requireAsciiTree(input);
  validatePolicy(policy);
  if (!object(input) || input.schema_version !== 'meshdraw-archive-input-v1'
      || !Array.isArray(input.rows) || input.rows.length > 3000) fail('ARCHIVE_INPUT_SHAPE');
  if (input.source_snapshot_sha256 !== policy.source_snapshot_sha256) fail('DECLARED_SOURCE_HASH_MISMATCH');
  const seen = new Map();
  for (const row of input.rows) {
    if (!object(row) || Object.keys(row).some(key => !ROW_FIELDS.includes(key))) fail('ROW_STRUCTURE');
    if (row.layer !== 'observation' || typeof row.parent_key !== 'string' || row.parent_key.length < 1
        || row.parent_key.length > 1024 || !object(row.fields)) fail('OBSERVATION_STRUCTURE');
    if (Object.keys(row.fields).some(key => !FIELDS.has(key))) fail('UNSAFE_FIELD');
    Object.values(row.fields).forEach(token);
    if (!row.fields.id || !['string', 'integer'].includes(row.fields.id.kind)) fail('MISSING_OBSERVATION_ID');
    const key = canonicalJson(stableId(row));
    if (seen.has(key)) {
      if (canonicalJson(seen.get(key).fields) !== canonicalJson(row.fields)) fail('OBSERVATION_ID_CHANGED_VALUES');
      fail('DUPLICATE_OBSERVATION_ID');
    }
    seen.set(key, row);
    integer(row.page, 0, Number.MAX_SAFE_INTEGER, 'LOCAL_INDEX_TYPE');
    integer(row.ordinal, 0, Number.MAX_SAFE_INTEGER, 'LOCAL_INDEX_TYPE');
    if (typeof row.request_utc !== 'string') fail('DOWNLOAD_TIME_TYPE');
  }
  const accepted = [], excluded = [], start = toUtcUs(policy.start), end = toUtcUs(policy.end);
  for (const row of [...input.rows].sort((a, b) => compare(stableId(a), stableId(b)))) {
    const reasons = []; let stamp = null;
    try { stamp = toUtcUs(value(row, 'timestamp')); } catch { reasons.push('UNKNOWN_OR_UNSUPPORTED_ARCHIVE_TIME'); }
    if (stamp !== null && !(start <= stamp && stamp < end)) reasons.push('OUTSIDE_ARCHIVE_WINDOW');
    if (value(row, 'direction') !== policy.direction) reasons.push('DIRECTION_NOT_RX');
    const observer = row.fields.observer_id;
    if (!observer || !['string', 'integer'].includes(observer.kind) || value(row, 'observer_id') === ''
        || value(row, 'observer_id') === null) reasons.push('MISSING_OBSERVER_ID');
    if (['rssi', 'snr'].some(metric => value(row, metric) === null)) reasons.push('MISSING_RF');
    if (reasons.length) { excluded.push({id: stableId(row), reasons}); continue; }
    const rf = ['rssi', 'snr'].map(metric => exact(value(row, metric)));
    if (rf.some(([n, d]) => (n < 0n ? -n : n) > 1000000n * d)) {
      excluded.push({id: stableId(row), reasons: ['RF_OUT_OF_PROFILE_RANGE']}); continue;
    }
    const strings = rf.map(plain);
    if (strings.some(text => text.length > 32)) fail('RF_QUARTER_LEXICAL_LIMIT');
    accepted.push({row, stamp, observer: token(observer), parent: row.parent_key, id: stableId(row), rf, plain: strings});
  }
  const groups = new Map(), ambiguities = new Map();
  for (const row of accepted) {
    const key = canonicalJson([row.observer, row.parent]);
    if (!groups.has(key)) groups.set(key, []); groups.get(key).push(row);
    const ambiguityKey = canonicalJson([row.observer, row.parent, row.stamp.toString()]);
    if (!ambiguities.has(ambiguityKey)) ambiguities.set(ambiguityKey, new Set());
    ambiguities.get(ambiguityKey).add(row.rf.map(([n, d]) => n + '/' + d).join(','));
  }
  const selected = [...groups.values()].map(rows => [...rows].sort((a, b) => compare([a.stamp, a.id], [b.stamp, b.id]))[0]);
  selected.sort((a, b) => compare([a.stamp, a.observer, a.parent, a.id], [b.stamp, b.observer, b.parent, b.id]));
  const inputHash = await digest(input);
  const result = {profile: 'archive-input-v1', status: 'ARCHIVE_NO_DRAW', reason: null,
    plan_sha256: await digest(policy), input_document_sha256: inputHash,
    frozen_input_hash_match: policy.input_document_sha256_before_calculation == null ? null
      : inputHash === policy.input_document_sha256_before_calculation,
    source_snapshot_sha256_declared: policy.source_snapshot_sha256,
    counts: {input_rows: input.rows.length, accepted_rows: accepted.length, selected_rows: selected.length,
      accepted_observers: new Set(accepted.map(row => canonicalJson(row.observer))).size,
      selected_observers: new Set(selected.map(row => canonicalJson(row.observer))).size},
    excluded, selected_ids: selected.map(row => row.id),
    ambiguity_group_count: [...ambiguities.values()].filter(values => values.size > 1).length,
    rf: null, mapping: null,
    meaning: 'Math on supplied saved archive numbers; not core-v0.2 replay, source authentication, completeness, finality or entropy proof'};
  if (selected.length < 8 || result.counts.selected_observers < 2) {
    result.reason = 'INSUFFICIENT_SELECTED_ROWS_OR_OBSERVERS'; return result;
  }
  const pairs = selected.map(row => row.plain.map(text => Number(quarter(text))));
  const packed = new Uint8Array(pairs.length * 8), view = new DataView(packed.buffer);
  pairs.forEach((pair, index) => {
    view.setInt32(index * 8, pair[0], false); view.setInt32(index * 8 + 4, pair[1], false);
  });
  const body = join(PREFIX, u32(pairs.length), packed), root = await sha256(body);
  const mapping = await mapDigest(root, policy.tickets, 8);
  result.status = mapping.index === null ? 'ARCHIVE_NO_DRAW' : 'ARCHIVE_DRAW';
  result.reason = mapping.index === null ? 'MAPPING_EXHAUSTED' : null;
  result.rf = {pairs, bytes_hex: toHex(body), sha256: root}; result.mapping = mapping;
  return result;
}

export async function verifyPackage(pkg) {
  canonicalJson(pkg); requireAsciiTree(pkg);
  fields(pkg, ['schema_version', 'mode', 'algorithm_version', 'projection', 'policy', 'snapshot', 'expected', 'manifest'], 'PUBLIC_PACKAGE_FIELDS');
  if (pkg.schema_version !== 'meshdraw-public-verification-v1'
      || !['SYNTHETIC', 'REVIEWED_PROJECTION'].includes(pkg.mode)
      || pkg.algorithm_version !== ALGORITHM_VERSION) fail('PUBLIC_PACKAGE_VERSION');
  fields(pkg.projection, ['policy', 'provenance', 'original_snapshot_sha256', 'original_plan_sha256', 'original_rf_sha256'], 'PROJECTION_FIELDS');
  if (pkg.projection.policy !== 'order-preserving-identifiers-v1'
      || pkg.projection.provenance !== 'NOT_INDEPENDENTLY_CONFIRMED') fail('PROJECTION_POLICY');
  for (const key of ['original_snapshot_sha256', 'original_plan_sha256', 'original_rf_sha256']) {
    if (key === 'original_rf_sha256' && pkg.projection[key] === null) continue;
    if (typeof pkg.projection[key] !== 'string' || !/^[0-9a-f]{64}(?![\s\S])/.test(pkg.projection[key])) fail('PROJECTION_HASH');
  }
  fields(pkg.manifest, ['policy', 'snapshot', 'expected', 'projection'], 'PUBLIC_MANIFEST_FIELDS');
  for (const name of ['policy', 'snapshot', 'expected', 'projection']) {
    if (await digest(pkg[name]) !== pkg.manifest[name]) fail('PUBLIC_MANIFEST_MISMATCH');
  }
  fields(pkg.expected, ['selection', 'calculation'], 'PUBLIC_EXPECTED_FIELDS');
  fields(pkg.policy, POLICY_FIELDS, 'PUBLIC_POLICY_FIELDS');
  validatePolicy(pkg.policy); checkSnapshot(pkg.snapshot);
  for (const row of pkg.snapshot.rows) {
    const allowed = row.layer === 'packet' ? ['id', 'first_seen', 'observation_count']
      : ['id', 'observer_id', 'timestamp', 'direction', 'rssi', 'snr'];
    if (Object.keys(row.fields).some(key => !allowed.includes(key))) fail('UNSAFE_PUBLIC_FIELDS');
    function alias(field, prefix) {
      if (field.kind === 'integer' && /^1[0-9]{6}(?![\s\S])/.test(field.value)
          || field.kind === 'string' && new RegExp('^' + prefix + '-[0-9]{6}(?![\\s\\S])').test(field.value)) return;
      fail('UNSAFE_PUBLIC_IDENTIFIER');
    }
    alias(row.fields.id, row.layer === 'packet' ? 'parent' : 'observation');
    const observer = row.fields.observer_id;
    if (observer && ['string', 'integer'].includes(observer.kind) && observer.value !== '') alias(observer, 'observer');
    else if (observer && (observer.kind !== 'null' || observer.value !== null)) fail('UNSAFE_PUBLIC_IDENTIFIER');
    for (const key of ['first_seen', 'timestamp']) {
      if (row.fields[key] && row.fields[key].value !== 'invalid-archive-time') toUtcUs(row.fields[key].value);
    }
    if (row.fields.direction && (row.fields.direction.kind !== 'string'
        || !['rx', 'not-rx'].includes(row.fields.direction.value))) fail('UNSAFE_PUBLIC_DIRECTION');
    toUtcUs(row.request_utc);
  }
  const filtered = windowFilter({source: {query: {since: pkg.policy.start, until: pkg.policy.end}}}, pkg.snapshot);
  const snapshotHash = await digest(pkg.snapshot);
  if (snapshotHash !== pkg.policy.source_snapshot_sha256) fail('DECLARED_SOURCE_HASH_MISMATCH');
  const input = {schema_version: 'meshdraw-archive-input-v1', source_snapshot_sha256: snapshotHash,
    archive_timestamp_meaning: 'Published archive field, physical times unknown',
    download_time_meaning: 'request_utc is extraction metadata, never RF input',
    retained: 'unknown-not-provided', rows: filtered.rows};
  const calculation = await evaluateArchive(pkg.policy, input);
  if (calculation.frozen_input_hash_match !== true) fail('FROZEN_INPUT_HASH_MISMATCH');
  if (canonicalJson(filtered.selection) !== canonicalJson(pkg.expected.selection)
      || canonicalJson(calculation) !== canonicalJson(pkg.expected.calculation)) fail('CALCULATION_MISMATCH');
  if ((calculation.rf?.sha256 ?? null) !== pkg.projection.original_rf_sha256) fail('ORIGINAL_RF_MISMATCH');
  return {status: 'MATCH', provenance: 'NOT_INDEPENDENTLY_CONFIRMED',
    selection: filtered.selection, calculation};
}
