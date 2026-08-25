const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";

const COOKIE_NAME = "libri_desempenho_session";
const SESSION_SECONDS = 60 * 60 * 12;

const DEFAULT_MAIN_HOST = "libriconvites.com.br";
const DEFAULT_MEDIA_HOST = "midia.libriconvites.com.br";
const DEFAULT_TIMEZONE = "America/Sao_Paulo";

const DEFAULT_EXCLUDED_SLUGS = new Set([
  "",
  "api",
  "editor",
  "motor",
  "painel-desempenho",
  "teste-motor",
  "favicon.ico",
  "robots.txt",
  "sitemap.xml",
  ".well-known"
]);


export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error("worker-desempenho:", error);

      return json(
        {
          error: publicErrorMessage(error)
        },
        500
      );
    }
  }
};


async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: securityHeaders()
    });
  }

  if (!url.pathname.startsWith("/api/desempenho")) {
    return json({ error: "Rota não encontrada." }, 404);
  }

  const missing = requiredEnvironment(env);

  if (missing.length) {
    return json(
      {
        error:
          `Configuração incompleta do Worker: ${missing.join(", ")}.`
      },
      500
    );
  }

  const endpoint = url.pathname
    .slice("/api/desempenho".length)
    .replace(/\/+$/, "") || "/";

  if (endpoint === "/login") {
    if (request.method !== "POST") {
      return methodNotAllowed();
    }

    return login(request, env);
  }

  if (endpoint === "/logout") {
    if (request.method !== "POST") {
      return methodNotAllowed();
    }

    return logout();
  }

  if (endpoint === "/sessao") {
    if (request.method !== "GET") {
      return methodNotAllowed();
    }

    const valid = await hasValidSession(request, env);

    if (!valid) {
      return unauthorized();
    }

    return json({ authenticated: true });
  }

  if (endpoint === "/resumo") {
    if (request.method !== "GET") {
      return methodNotAllowed();
    }

    const valid = await hasValidSession(request, env);

    if (!valid) {
      return unauthorized();
    }

    const period = normalizePeriod(url.searchParams.get("periodo"));

    return dashboardSummary(env, period);
  }

  return json({ error: "Rota não encontrada." }, 404);
}


function requiredEnvironment(env) {
  const required = [
    "ADMIN_PASSWORD",
    "SESSION_SECRET",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ZONE_ID"
  ];

  return required.filter((key) => !String(env[key] || "").trim());
}


function methodNotAllowed() {
  return json({ error: "Método não permitido." }, 405);
}


function unauthorized() {
  return json({ error: "Sessão não autenticada." }, 401);
}


function publicErrorMessage(error) {
  const fallback =
    "Não foi possível consultar o Cloudflare Analytics.";

  let message = String(
    error?.message ||
    error ||
    ""
  ).trim();

  if (!message) {
    return fallback;
  }

  // Nunca devolver credenciais, IDs longos ou tokens na resposta pública.
  message = message
    .replace(
      /Bearer\s+[A-Za-z0-9._~+\/=-]+/gi,
      "Bearer [oculto]"
    )
    .replace(
      /\b[a-f0-9]{32}\b/gi,
      "[id oculto]"
    )
    .replace(
      /\b[A-Za-z0-9_-]{40,}\b/g,
      "[valor oculto]"
    );

  if (message.length > 420) {
    message = `${message.slice(0, 420)}…`;
  }

  return `Cloudflare Analytics: ${message}`;
}


async function login(request, env) {
  let body = {};

  try {
    body = await request.json();
  } catch (_) {
    return json({ error: "Requisição inválida." }, 400);
  }

  const provided = String(body.password || "");
  const expected = String(env.ADMIN_PASSWORD || "");

  if (!constantTimeTextEqual(provided, expected)) {
    return json({ error: "Senha incorreta." }, 401);
  }

  const token = await createSessionToken(env.SESSION_SECRET);

  return json(
    {
      authenticated: true
    },
    200,
    {
      "Set-Cookie": buildSessionCookie(token)
    }
  );
}


function logout() {
  return json(
    {
      authenticated: false
    },
    200,
    {
      "Set-Cookie":
        `${COOKIE_NAME}=; Path=/api/desempenho; Max-Age=0; ` +
        "HttpOnly; Secure; SameSite=Strict"
    }
  );
}


async function hasValidSession(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const token = cookies[COOKIE_NAME];

  if (!token) {
    return false;
  }

  return verifySessionToken(token, env.SESSION_SECRET);
}


function parseCookies(header) {
  const result = {};

  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");

    if (index < 0) {
      continue;
    }

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key) {
      result[key] = value;
    }
  }

  return result;
}


function buildSessionCookie(token) {
  return (
    `${COOKIE_NAME}=${token}; ` +
    "Path=/api/desempenho; " +
    `Max-Age=${SESSION_SECONDS}; ` +
    "HttpOnly; Secure; SameSite=Strict"
  );
}


async function createSessionToken(secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const payload = `v1.${expires}.${nonce}`;
  const signature = await sign(payload, secret);

  return `${payload}.${signature}`;
}


async function verifySessionToken(token, secret) {
  const parts = String(token || "").split(".");

  if (parts.length !== 4 || parts[0] !== "v1") {
    return false;
  }

  const [version, expiresText, nonce, signature] = parts;
  const expires = Number(expiresText);

  if (
    !Number.isFinite(expires) ||
    expires <= Math.floor(Date.now() / 1000) ||
    nonce.length < 16
  ) {
    return false;
  }

  const payload = `${version}.${expiresText}.${nonce}`;

  try {
    const key = await importHmacKey(secret);

    return crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecode(signature),
      new TextEncoder().encode(payload)
    );
  } catch (_) {
    return false;
  }
}


async function sign(value, secret) {
  const key = await importHmacKey(secret);

  const result = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return base64UrlEncode(result);
}


async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );
}


function base64UrlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}


function base64UrlDecode(value) {
  let base64 = String(value)
    .replaceAll("-", "+")
    .replaceAll("_", "/");

  while (base64.length % 4) {
    base64 += "=";
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}


function constantTimeTextEqual(a, b) {
  const encoder = new TextEncoder();
  const left = encoder.encode(String(a));
  const right = encoder.encode(String(b));

  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;

  for (let index = 0; index < length; index += 1) {
    difference |=
      (left[index] || 0) ^
      (right[index] || 0);
  }

  return difference === 0;
}


async function dashboardSummary(env, period) {
  const timezone =
    String(env.APP_TIMEZONE || DEFAULT_TIMEZONE).trim() ||
    DEFAULT_TIMEZONE;

  const mainHost =
    String(env.MAIN_HOST || DEFAULT_MAIN_HOST).trim().toLowerCase();

  const mediaHost =
    String(env.MEDIA_HOST || DEFAULT_MEDIA_HOST).trim().toLowerCase();

  const range = dateRange(period, timezone);

  const graph = await queryAnalytics(env, {
    start: range.start.toISOString(),
    end: range.end.toISOString(),
    mainHost
  });

  const excluded = buildExcludedSlugs(env.EXCLUDED_SLUGS);

  const invites = aggregateInvites(
    graph.trafficGroups,
    {
      mainHost,
      mediaHost,
      excluded
    }
  );

  const timeline = aggregateTimeline(
    graph.timelineGroups,
    {
      mainHost,
      timezone,
      excluded,
      start: range.start,
      end: range.end
    }
  );

  invites.sort((a, b) => {
    if (b.visits !== a.visits) {
      return b.visits - a.visits;
    }

    return b.bytes - a.bytes;
  });

  const totals = invites.reduce(
    (acc, invite) => {
      acc.visits += invite.visits;
      acc.requests += invite.requests;
      acc.bytes += invite.bytes;

      if (invite.visits > 0) {
        acc.activeInvites += 1;
      }

      return acc;
    },
    {
      visits: 0,
      requests: 0,
      bytes: 0,
      activeInvites: 0
    }
  );

  const topInvite =
    invites.find((invite) => invite.visits > 0) || null;

  const topBandwidth =
    [...invites].sort((a, b) => b.bytes - a.bytes)[0] || null;

  const peakDay =
    [...timeline].sort((a, b) => b.visits - a.visits)[0] || null;

  return json({
    period,
    range: {
      start: range.start.toISOString(),
      end: range.end.toISOString(),
      timezone
    },
    totals,
    highlights: {
      topInvite: compactInvite(topInvite),
      topBandwidth: compactInvite(topBandwidth),
      peakDay
    },
    timeline,
    invites,
    updatedAt: new Date().toISOString()
  });
}


function compactInvite(invite) {
  if (!invite) {
    return null;
  }

  return {
    title: invite.title,
    path: invite.path,
    visits: invite.visits,
    requests: invite.requests,
    bytes: invite.bytes
  };
}


let analyticsSettingsCache = {
  expiresAt: 0,
  value: null
};


async function queryAnalytics(env, { start, end, mainHost }) {
  const settings = await queryAnalyticsSettings(env);

  const maxDurationSeconds = Math.max(
    60,
    safeNumber(settings.maxDuration) || 86400
  );

  const notOlderThanSeconds =
    safeNumber(settings.notOlderThan);

  if (notOlderThanSeconds > 0) {
    const earliestAllowed =
      Date.now() - (notOlderThanSeconds * 1000);

    if (
      new Date(start).getTime() <
      earliestAllowed - (5 * 60 * 1000)
    ) {
      const availableDays = Math.max(
        1,
        Math.floor(notOlderThanSeconds / 86400)
      );

      throw new Error(
        `Seu plano Cloudflare disponibiliza aproximadamente ${availableDays} ` +
        `${availableDays === 1 ? "dia" : "dias"} de histórico para este dataset. ` +
        "Escolha um período menor."
      );
    }
  }

  const chunks = splitTimeRange(
    new Date(start),
    new Date(end),
    maxDurationSeconds
  );

  const results = await mapInBatches(
    chunks,
    5,
    (chunk) =>
      queryAnalyticsChunk(env, {
        start: chunk.start.toISOString(),
        end: chunk.end.toISOString(),
        mainHost
      })
  );

  return {
    trafficGroups:
      results.flatMap((item) => item.trafficGroups),

    timelineGroups:
      results.flatMap((item) => item.timelineGroups)
  };
}


async function queryAnalyticsSettings(env) {
  if (
    analyticsSettingsCache.value &&
    Date.now() < analyticsSettingsCache.expiresAt
  ) {
    return analyticsSettingsCache.value;
  }

  const query = `
    query LibriAnalyticsSettings($zoneTag: string) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          settings {
            httpRequestsAdaptiveGroups {
              enabled
              maxDuration
              maxPageSize
              notOlderThan
            }
          }
        }
      }
    }
  `;

  const payload = await cloudflareGraphQL(
    env,
    query,
    {
      zoneTag: String(env.CLOUDFLARE_ZONE_ID)
    }
  );

  const settings =
    payload?.data?.viewer?.zones?.[0]
      ?.settings
      ?.httpRequestsAdaptiveGroups;

  if (!settings) {
    throw new Error(
      "Não foi possível descobrir os limites de Analytics desta zona."
    );
  }

  if (settings.enabled === false) {
    throw new Error(
      "O dataset httpRequestsAdaptiveGroups não está habilitado para esta zona."
    );
  }

  analyticsSettingsCache = {
    value: settings,
    expiresAt: Date.now() + (5 * 60 * 1000)
  };

  return settings;
}


function splitTimeRange(start, end, maxDurationSeconds) {
  const startMs = start.getTime();
  const endMs = end.getTime();

  if (
    !Number.isFinite(startMs) ||
    !Number.isFinite(endMs) ||
    endMs <= startMs
  ) {
    return [];
  }

  const maxMs =
    Math.max(60, maxDurationSeconds) * 1000;

  const chunks = [];
  let cursor = startMs;

  while (cursor < endMs) {
    const next = Math.min(
      cursor + maxMs,
      endMs
    );

    chunks.push({
      start: new Date(cursor),
      end: new Date(next)
    });

    cursor = next;
  }

  return chunks;
}


async function mapInBatches(items, batchSize, mapper) {
  const results = [];

  for (
    let index = 0;
    index < items.length;
    index += batchSize
  ) {
    const batch = items.slice(
      index,
      index + batchSize
    );

    const batchResults = await Promise.all(
      batch.map(mapper)
    );

    results.push(...batchResults);
  }

  return results;
}


async function queryAnalyticsChunk(
  env,
  {
    start,
    end,
    mainHost
  }
) {
  const query = `
    query LibriPerformance(
      $zoneTag: string
      $trafficFilter: filter
      $timelineFilter: filter
    ) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {

          trafficGroups: httpRequestsAdaptiveGroups(
            limit: 10000
            filter: $trafficFilter
          ) {
            count
            sum {
              visits
              edgeResponseBytes
            }
            dimensions {
              clientRequestHTTPHost
              clientRequestPath
            }
          }

          timelineGroups: httpRequestsAdaptiveGroups(
            limit: 10000
            orderBy: [datetimeHour_ASC]
            filter: $timelineFilter
          ) {
            count
            sum {
              visits
            }
            dimensions {
              datetimeHour
              clientRequestPath
              clientRequestHTTPHost
            }
          }

        }
      }
    }
  `;

  const variables = {
    zoneTag: String(env.CLOUDFLARE_ZONE_ID),

    trafficFilter: {
      datetime_geq: start,
      datetime_lt: end,
      requestSource: "eyeball"
    },

    timelineFilter: {
      datetime_geq: start,
      datetime_lt: end,
      requestSource: "eyeball",
      clientRequestHTTPHost: mainHost
    }
  };

  const payload = await cloudflareGraphQL(
    env,
    query,
    variables
  );

  const zones = payload?.data?.viewer?.zones;

  if (!Array.isArray(zones) || !zones.length) {
    throw new Error(
      "A zona do Cloudflare não foi encontrada. Confira o Zone ID e o token."
    );
  }

  return {
    trafficGroups:
      Array.isArray(zones[0].trafficGroups)
        ? zones[0].trafficGroups
        : [],

    timelineGroups:
      Array.isArray(zones[0].timelineGroups)
        ? zones[0].timelineGroups
        : []
  };
}


async function cloudflareGraphQL(
  env,
  query,
  variables
) {
  const response = await fetch(
    GRAPHQL_ENDPOINT,
    {
      method: "POST",
      headers: {
        "Authorization":
          `Bearer ${String(env.CLOUDFLARE_API_TOKEN)}`,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        query,
        variables
      })
    }
  );

  let payload = {};

  try {
    payload = await response.json();
  } catch (_) {
    throw new Error(
      "O Cloudflare retornou uma resposta inválida."
    );
  }

  if (!response.ok) {
    console.error(
      "Cloudflare GraphQL HTTP error:",
      response.status,
      payload
    );

    throw new Error(
      payload?.errors?.[0]?.message ||
      `O Cloudflare respondeu com HTTP ${response.status}.`
    );
  }

  if (
    Array.isArray(payload.errors) &&
    payload.errors.length
  ) {
    console.error(
      "Cloudflare GraphQL errors:",
      JSON.stringify(payload.errors)
    );

    throw new Error(
      payload.errors[0]?.message ||
      "A consulta de Analytics foi recusada pelo Cloudflare."
    );
  }

  return payload;
}


function aggregateInvites(
  groups,
  {
    mainHost,
    mediaHost,
    excluded
  }
) {
  const map = new Map();

  for (const group of Array.isArray(groups) ? groups : []) {
    const dimensions = group?.dimensions || {};

    const host = String(
      dimensions.clientRequestHTTPHost || ""
    ).toLowerCase();

    if (host !== mainHost && host !== mediaHost) {
      continue;
    }

    const path = normalizePath(
      dimensions.clientRequestPath || "/"
    );

    const slug = slugFromPath(path);

    if (!isInviteSlug(slug, excluded)) {
      continue;
    }

    const item = getInviteRecord(map, slug);

    const requests = safeNumber(group?.count);
    const bytes = safeNumber(group?.sum?.edgeResponseBytes);

    item.requests += requests;
    item.bytes += bytes;

    if (
      host === mainHost &&
      isInvitationPagePath(path, slug)
    ) {
      item.visits += safeNumber(group?.sum?.visits);
    }
  }

  return [...map.values()].map((invite) => ({
    ...invite,
    visits: Math.round(invite.visits),
    requests: Math.round(invite.requests),
    bytes: Math.round(invite.bytes)
  }));
}


function aggregateTimeline(
  groups,
  {
    mainHost,
    timezone,
    excluded,
    start,
    end
  }
) {
  const daily = createDailyBuckets(start, end, timezone);

  for (const group of Array.isArray(groups) ? groups : []) {
    const dimensions = group?.dimensions || {};

    const host = String(
      dimensions.clientRequestHTTPHost || ""
    ).toLowerCase();

    if (host !== mainHost) {
      continue;
    }

    const path = normalizePath(
      dimensions.clientRequestPath || "/"
    );

    const slug = slugFromPath(path);

    if (
      !isInviteSlug(slug, excluded) ||
      !isInvitationPagePath(path, slug)
    ) {
      continue;
    }

    const hour = String(dimensions.datetimeHour || "");

    if (!hour) {
      continue;
    }

    const date = localDateKey(new Date(hour), timezone);

    if (!daily.has(date)) {
      daily.set(date, 0);
    }

    daily.set(
      date,
      safeNumber(daily.get(date)) +
      safeNumber(group?.sum?.visits)
    );
  }

  return [...daily.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, visits]) => ({
      date,
      visits: Math.round(visits)
    }));
}


function getInviteRecord(map, slug) {
  if (!map.has(slug)) {
    map.set(slug, {
      slug,
      title: titleFromSlug(slug),
      path: `/${slug}/`,
      visits: 0,
      requests: 0,
      bytes: 0
    });
  }

  return map.get(slug);
}


function normalizePath(value) {
  let path = String(value || "/");

  try {
    path = decodeURIComponent(path);
  } catch (_) {
    // Mantém o valor original se houver encoding inválido.
  }

  path = path.split("?")[0].split("#")[0];

  if (!path.startsWith("/")) {
    path = `/${path}`;
  }

  path = path.replace(/\/{2,}/g, "/");

  return path || "/";
}


function slugFromPath(path) {
  return normalizePath(path)
    .split("/")
    .filter(Boolean)[0] || "";
}


function isInvitationPagePath(path, slug) {
  const normalized = normalizePath(path);

  return (
    normalized === `/${slug}` ||
    normalized === `/${slug}/` ||
    normalized === `/${slug}/index.html`
  );
}


function isInviteSlug(slug, excluded) {
  if (!slug || excluded.has(slug.toLowerCase())) {
    return false;
  }

  if (slug.startsWith(".")) {
    return false;
  }

  if (slug.includes(".")) {
    return false;
  }

  return /^[a-z0-9][a-z0-9-]*$/i.test(slug);
}


function buildExcludedSlugs(extra) {
  const result = new Set(DEFAULT_EXCLUDED_SLUGS);

  String(extra || "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .forEach((item) => result.add(item));

  return result;
}


function titleFromSlug(slug) {
  const smallWords = new Set([
    "a",
    "as",
    "o",
    "os",
    "da",
    "das",
    "de",
    "do",
    "dos",
    "e"
  ]);

  const words = String(slug || "")
    .split("-")
    .filter(Boolean);

  return words
    .map((word, index) => {
      const lower = word.toLowerCase();

      if (index > 0 && smallWords.has(lower)) {
        return lower;
      }

      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}


function safeNumber(value) {
  const number = Number(value || 0);

  return Number.isFinite(number)
    ? number
    : 0;
}


function normalizePeriod(value) {
  return ["1d", "7d", "30d"].includes(value)
    ? value
    : "7d";
}


function dateRange(period, timezone) {
  const days =
    period === "1d"
      ? 1
      : period === "30d"
        ? 30
        : 7;

  const end = new Date();
  const local = zonedParts(end, timezone);

  const calendar = new Date(
    Date.UTC(
      local.year,
      local.month - 1,
      local.day,
      12,
      0,
      0
    )
  );

  calendar.setUTCDate(
    calendar.getUTCDate() - (days - 1)
  );

  const start = zonedDateTimeToUtc(
    {
      year: calendar.getUTCFullYear(),
      month: calendar.getUTCMonth() + 1,
      day: calendar.getUTCDate(),
      hour: 0,
      minute: 0,
      second: 0
    },
    timezone
  );

  return {
    start,
    end
  };
}


function createDailyBuckets(start, end, timezone) {
  const map = new Map();

  const startParts = zonedParts(start, timezone);
  const endParts = zonedParts(end, timezone);

  const cursor = new Date(
    Date.UTC(
      startParts.year,
      startParts.month - 1,
      startParts.day,
      12
    )
  );

  const finish = new Date(
    Date.UTC(
      endParts.year,
      endParts.month - 1,
      endParts.day,
      12
    )
  );

  while (cursor <= finish) {
    const key = [
      cursor.getUTCFullYear(),
      String(cursor.getUTCMonth() + 1).padStart(2, "0"),
      String(cursor.getUTCDate()).padStart(2, "0")
    ].join("-");

    map.set(key, 0);
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }

  return map;
}


function localDateKey(date, timezone) {
  const parts = zonedParts(date, timezone);

  return [
    parts.year,
    String(parts.month).padStart(2, "0"),
    String(parts.day).padStart(2, "0")
  ].join("-");
}


function zonedDateTimeToUtc(parts, timezone) {
  const guess = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour || 0,
    parts.minute || 0,
    parts.second || 0
  );

  let candidate = guess;

  for (let index = 0; index < 3; index += 1) {
    const actual = zonedParts(
      new Date(candidate),
      timezone
    );

    const actualAsUtc = Date.UTC(
      actual.year,
      actual.month - 1,
      actual.day,
      actual.hour,
      actual.minute,
      actual.second
    );

    const desiredAsUtc = Date.UTC(
      parts.year,
      parts.month - 1,
      parts.day,
      parts.hour || 0,
      parts.minute || 0,
      parts.second || 0
    );

    const delta = desiredAsUtc - actualAsUtc;

    if (delta === 0) {
      break;
    }

    candidate += delta;
  }

  return new Date(candidate);
}


function zonedParts(date, timezone) {
  const formatter = new Intl.DateTimeFormat(
    "en-CA",
    {
      timeZone: timezone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23"
    }
  );

  const values = {};

  for (const part of formatter.formatToParts(date)) {
    if (part.type !== "literal") {
      values[part.type] = part.value;
    }
  }

  return {
    year: Number(values.year),
    month: Number(values.month),
    day: Number(values.day),
    hour: Number(values.hour),
    minute: Number(values.minute),
    second: Number(values.second)
  };
}


function json(body, status = 200, extraHeaders = {}) {
  return new Response(
    JSON.stringify(body),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control":
          "private, no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        ...securityHeaders(),
        ...extraHeaders
      }
    }
  );
}


function securityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer"
  };
}
