import * as verifier from './verifier.mjs';
const { parsePackageText, verifyPackage, digest } = verifier;
const UI_CONTRACT = 'meshdraw-web-v3';
const STATE_FORMAT = 'meshdraw-public-state-v2';

const byId = (id) => document.getElementById(id);
const phases = {
  OPEN: 'Приём заявок открыт',
  CLOSING: 'Приём завершён, проверяем список',
  CLOSED: 'Приём завершён, проверяем список',
  DRAINED: 'Приём завершён, проверяем список',
  FROZEN: 'Список зафиксирован',
  DRAWN: 'Результат сохранён',
  DRAW_FAILED: 'Техническая задержка: результат не определён',
  WAITING: 'Ожидаем закреплённое время расчёта',
  RUNNING: 'Получаем данные и сохраняем расчёт',
};
let savedState = null;
let verificationPackage = null;

function status(message, state = '') {
  const node = byId('verification-status');
  node.textContent = message;
  node.dataset.state = state;
}

async function readPrepared(name, optional = false) {
  // Only prepared local release files are read; recalculation never fetches RF.
  const response = await fetch(new URL(name, import.meta.url), {
    credentials: 'omit', redirect: 'error', cache: 'no-store',
    signal: AbortSignal.timeout(10000),
  });
  if (optional && response.status === 404) return null;
  if (!response.ok) throw new Error('PREPARED_FILE_UNAVAILABLE');
  return parsePackageText(await response.text());
}

function validateView(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('PUBLIC_STATE_INVALID');
  for (const key of ['contest_id', 'title', 'prize', 'rules_text', 'opens_at', 'cutoff_at']) {
    if (typeof value[key] !== 'string' || value[key].length > 4000) throw new Error('PUBLIC_STATE_INVALID');
  }
  if (!Object.hasOwn(phases, value.phase) || typeof value.synthetic !== 'boolean'
      || !Array.isArray(value.tickets) || value.tickets.length > 10000
      || value.tickets.some((ticket) => typeof ticket !== 'string' || ticket.length < 1
        || ticket.length > 32 || /[^0-9]/.test(ticket))
      || new Set(value.tickets.map((ticket) => BigInt(ticket).toString())).size !== value.tickets.length
      || (value.winner !== null && !value.tickets.includes(value.winner))) {
    throw new Error('PUBLIC_STATE_INVALID');
  }
  const validTime = text => typeof text === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(text) && Number.isFinite(Date.parse(text));
  if (!validTime(value.opens_at) || !validTime(value.cutoff_at)
      || Date.parse(value.cutoff_at) <= Date.parse(value.opens_at)) throw new Error('PUBLIC_DATES_INVALID');
  if (value.archive_plan && (!validTime(value.archive_plan.start) || !validTime(value.archive_plan.end)
      || !validTime(value.archive_plan.read_at))) throw new Error('PUBLIC_DATES_INVALID');
  return value;
}

function displayView(value) {
  document.title = value.title;
  byId('contest-title').textContent = value.title;
  const now = Date.now();
  byId('contest-state').textContent = value.synthetic ? 'Учебный режим' : value.phase === 'OPEN' && now < Date.parse(value.opens_at)
    ? 'Приём ещё не начался' : value.phase === 'OPEN' && now >= Date.parse(value.cutoff_at)
      ? phases.CLOSING : phases[value.phase];
  byId('contest-state').dataset.tone = value.phase === 'DRAW_FAILED' ? 'error' : 'ready';
  byId('synthetic-banner').hidden = !value.synthetic;
  byId('prize').textContent = `Приз: ${value.prize}`;
  byId('prize').hidden = value.synthetic || !value.prize;
  const drawn = value.winner !== null;
  byId('result-panel').dataset.result = drawn ? 'available' : 'empty';
  byId('winner-label').textContent = drawn
    ? (value.synthetic ? 'Учебный билет' : 'Билет победителя')
    : 'Победитель ещё не объявлен';
  byId('saved-result').textContent = drawn ? `№${value.winner}` : 'Ожидаем результат';
  byId('result-note').textContent = drawn
    ? (value.synthetic
      ? 'Учебный результат по синтетическому пакету.'
      : 'Это сохранённый результат. Его можно проверить по опубликованному пакету.')
    : value.phase === 'DRAW_FAILED' ? 'Расчёт не завершён. Дальнейшие действия сообщит организатор.'
      : 'Сохранённый результат появится после завершения приёма и расчёта.';
  byId('rules').textContent = value.rules_text;
  const utc = text => new Intl.DateTimeFormat('ru-RU', {timeZone:'UTC',dateStyle:'long',timeStyle:'medium'}).format(new Date(text)) + ' (UTC)';
  byId('opens-at').textContent = value.synthetic ? 'Не объявлено' : utc(value.opens_at);
  byId('cutoff-at').textContent = value.synthetic ? 'Не объявлено' : utc(value.cutoff_at);
  byId('ticket-count').textContent = String(value.tickets.length);
  byId('no-tickets').textContent = 'В опубликованном списке пока нет билетов.';
  byId('no-tickets').hidden = value.tickets.length > 0;
  const tickets = document.createDocumentFragment();
  for (const ticket of value.tickets) {
    const item = document.createElement('li');
    item.textContent = ticket;
    if (ticket === value.winner) item.dataset.winner = 'true';
    tickets.append(item);
  }
  byId('tickets').replaceChildren(tickets);
  if (value.archive_plan) {
    byId('archive-section').hidden = false;
    byId('archive-window').textContent = `${utc(value.archive_plan.start)} — ${utc(value.archive_plan.end)}`;
    byId('archive-read-at').textContent = utc(value.archive_plan.read_at);
    byId('plan-hash').textContent = value.plan_sha256 || 'Не опубликована';
  }
}

function checkContestBinding(pkg, result) {
  if (JSON.stringify(pkg.policy.tickets) !== JSON.stringify(savedState.tickets)
      || result.calculation.mapping?.ticket !== savedState.winner
      || pkg.projection.original_plan_sha256 !== savedState.plan_sha256
      || (pkg.mode === 'SYNTHETIC') !== savedState.synthetic) {
    throw new Error('PUBLIC_STATE_PACKAGE_MISMATCH');
  }
}

function detailsFor(result) {
  const calculation = result.calculation;
  return JSON.stringify({
    selection: result.selection,
    selected_ids: calculation.selected_ids,
    counts: calculation.counts,
    excluded: calculation.excluded,
    ambiguity_group_count: calculation.ambiguity_group_count,
    quantized_pairs: calculation.rf?.pairs ?? null,
    rf_bytes_hex: calculation.rf?.bytes_hex ?? null,
    rf_sha256: calculation.rf?.sha256 ?? null,
    ticket_index_zero_based: calculation.mapping?.index ?? null,
    ticket: calculation.mapping?.ticket ?? null,
    mapping_words_used: calculation.mapping?.words_used ?? null,
    independent_provenance: 'NOT_CONFIRMED',
  }, null, 2);
}

byId('recalculate').addEventListener('click', async () => {
  const button = byId('recalculate');
  button.disabled = true;
  button.textContent = 'Пересчитываем…';
  status('Пересчитываем опубликованный пакет…');
  byId('calculation-output').hidden = true;
  byId('steps-note').hidden = false;
  try {
    const result = await verifyPackage(verificationPackage);
    if (typeof savedState.verification_sha256 !== 'string' || await digest(verificationPackage) !== savedState.verification_sha256) {
      throw new Error('PUBLIC_PACKAGE_BINDING_MISMATCH');
    }
    if (result.status !== 'MATCH') throw new Error('CALCULATION_MISMATCH');
    checkContestBinding(verificationPackage, result);
    byId('calculation-output').textContent = detailsFor(result);
    byId('calculation-output').hidden = false;
    byId('steps-note').hidden = true;
    const label = savedState.synthetic ? 'Учебный билет' : 'Победитель — билет';
    status(`Расчёт совпал. ${label} №${result.calculation.mapping.ticket}.`, 'match');
  } catch {
    status('Расчёт не подтверждён: пакет повреждён, отличается от опубликованного результата или не поддерживается. Скачайте пакет и обратитесь к организатору.', 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Пересчитать';
  }
});

async function load() {
  try {
    const metadata = await readPrepared('RELEASE.json');
    const envelope = await readPrepared('result.json');
    if (metadata.schema_version !== 'meshdraw-public-release-v2'
        || metadata.ui_contract !== UI_CONTRACT || metadata.state_format !== STATE_FORMAT
        || metadata.algorithm_version !== verifier.ALGORITHM_VERSION
        || metadata.archive_profile !== 'archive-input-v1'
        || metadata.verification_format !== 'meshdraw-public-verification-v1'
        || verifier.UI_CONTRACT !== UI_CONTRACT
        || document.querySelector('meta[name="meshdraw-ui-contract"]')?.content !== UI_CONTRACT
        || envelope.schema_version !== STATE_FORMAT || envelope.ui_contract !== UI_CONTRACT) {
      throw new Error('INCOMPATIBLE_RELEASE_FILES');
    }
    savedState = validateView(envelope.state);
    if (metadata.source_mode !== (savedState.synthetic ? 'SYNTHETIC' : 'REVIEWED_PROJECTION')) {
      throw new Error('INCOMPATIBLE_RELEASE_MODE');
    }
    displayView(savedState);
    byId('main')?.setAttribute('aria-busy', 'false');
  } catch {
    byId('contest-state').textContent = 'Публичное состояние конкурса недоступно.';
    byId('contest-state').dataset.tone = 'error';
    if (byId('result-panel')) byId('result-panel').dataset.result = 'error';
    byId('saved-result').textContent = 'Не загружен';
    if (byId('result-note')) byId('result-note').textContent = 'Не удалось загрузить конкурс. Обновите страницу или обратитесь к организатору.';
    byId('no-tickets').textContent = 'Список не загружен.';
    byId('main')?.setAttribute('aria-busy', 'false');
    status('Комплект недоступен, повреждён или содержит несовместимые версии файлов. Откройте страницу по HTTPS или через локальный HTTP-сервер и проверьте комплект целиком.', 'error');
    return;
  }
  try {
    verificationPackage = await readPrepared('verification.json', true);
    if (!verificationPackage || savedState.winner === null) {
      status('Проверочный пакет результата пока не опубликован. Пересчёт станет доступен после сохранения и подготовки результата.');
      return;
    }
    if (!globalThis.crypto?.subtle || typeof BigInt !== 'function') throw new Error('BROWSER_UNSUPPORTED');
    byId('package-download').hidden = false;
    byId('recalculate').disabled = false;
    status('Проверочный пакет загружен. Нажмите «Пересчитать».');
  } catch {
    status('Проверочный пакет недоступен или не поддерживается браузером. Нужны HTTPS (либо localhost), BigInt и Web Crypto. Обратитесь к организатору за исправленным комплектом.', 'error');
  }
}

await load();
