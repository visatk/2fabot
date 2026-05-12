import { Hono } from 'hono';
import * as OTPAuth from 'otpauth';

// ─── TYPES ──────────────────────────────────────────────────────────────────

export type Bindings = {
  DB: D1Database;
  TELEGRAM_BOT_TOKEN: string;
  WEBHOOK_SECRET: string; // Cloudflare Secret — set via: wrangler secret put WEBHOOK_SECRET
};

type TelegramFrom = {
  id: number;
  username?: string;
  first_name?: string;
};

type TelegramMessage = {
  chat: { id: number };
  from: TelegramFrom;
  text?: string;
  message_id: number;
};

type TelegramCallbackQuery = {
  id: string;
  from: TelegramFrom;
  message: TelegramMessage;
  data: string;
};

type TelegramUpdate = {
  update_id: number;
  message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
};

type RateLimitRecord = {
  count: number;
  window_start: number;
};

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_MS = 60_000;      // 1 minute window
const RATE_LIMIT_MAX_REQUESTS = 20;       // max 20 actions/min per user
const MAX_SERVICE_NAME_LENGTH = 50;
const MAX_SERVICES_PER_USER = 50;
const BOT_VERSION = '2.0.0';

// ─── APP ─────────────────────────────────────────────────────────────────────

const app = new Hono<{ Bindings: Bindings }>();

// ─── STRUCTURED LOGGER ───────────────────────────────────────────────────────

const log = {
  info: (msg: string, meta?: Record<string, unknown>) =>
    console.log(JSON.stringify({ level: 'INFO', msg, ...meta, ts: Date.now() })),
  warn: (msg: string, meta?: Record<string, unknown>) =>
    console.warn(JSON.stringify({ level: 'WARN', msg, ...meta, ts: Date.now() })),
  error: (msg: string, meta?: Record<string, unknown>) =>
    console.error(JSON.stringify({ level: 'ERROR', msg, ...meta, ts: Date.now() })),
};

// ─── TELEGRAM API ────────────────────────────────────────────────────────────

async function callTelegram(token: string, method: string, payload: Record<string, unknown>): Promise<boolean> {
  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const body = await res.text();
      log.warn(`Telegram API error [${method}]`, { status: res.status, body });
      return false;
    }
    return true;
  } catch (err) {
    log.error(`Telegram API fetch failed [${method}]`, { err: String(err) });
    return false;
  }
}

// MarkdownV2 — escape all reserved characters
function esc(text: string): string {
  return String(text).replace(/[_*[\]()~`>#+\-=|{}.!\\]/g, '\\$&');
}

// ─── SECURITY: WEBHOOK VALIDATION ────────────────────────────────────────────

function validateWebhookSecret(request: Request, secret: string): boolean {
  const header = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
  if (!header || !secret) return false;
  // Constant-time comparison to prevent timing attacks
  if (header.length !== secret.length) return false;
  let diff = 0;
  for (let i = 0; i < header.length; i++) {
    diff |= header.charCodeAt(i) ^ secret.charCodeAt(i);
  }
  return diff === 0;
}

// ─── SECURITY: INPUT VALIDATION ──────────────────────────────────────────────

function isValidBase32(secret: string): boolean {
  return /^[A-Z2-7]+=*$/.test(secret) && secret.replace(/=/g, '').length >= 8;
}

function sanitizeServiceName(name: string): string {
  // Allow alphanumeric, spaces, hyphens, underscores, dots
  return name.replace(/[^a-zA-Z0-9 _\-\.@]/g, '').trim().slice(0, MAX_SERVICE_NAME_LENGTH);
}

// ─── SECURITY: RATE LIMITER (D1-backed) ──────────────────────────────────────

async function isRateLimited(db: D1Database, userId: number): Promise<boolean> {
  try {
    const record = await db
      .prepare('SELECT count, window_start FROM rate_limits WHERE user_id = ?')
      .bind(userId)
      .first<RateLimitRecord>();

    const now = Date.now();

    if (!record || now - record.window_start > RATE_LIMIT_WINDOW_MS) {
      // New window
      await db
        .prepare(`
          INSERT INTO rate_limits (user_id, count, window_start)
          VALUES (?, 1, ?)
          ON CONFLICT(user_id) DO UPDATE SET count = 1, window_start = excluded.window_start
        `)
        .bind(userId, now)
        .run();
      return false;
    }

    if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
      log.warn('Rate limit hit', { userId });
      return true;
    }

    await db
      .prepare('UPDATE rate_limits SET count = count + 1 WHERE user_id = ?')
      .bind(userId)
      .run();
    return false;
  } catch {
    // Fail open — don't block on DB error
    return false;
  }
}

// ─── USER MANAGEMENT ─────────────────────────────────────────────────────────

async function upsertUser(db: D1Database, from: TelegramFrom): Promise<void> {
  await db
    .prepare(`
      INSERT INTO users (user_id, username, first_name, last_active)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id) DO UPDATE SET
        username   = excluded.username,
        first_name = excluded.first_name,
        last_active = CURRENT_TIMESTAMP
    `)
    .bind(from.id, from.username ?? null, from.first_name ?? null)
    .run();
}

// ─── TOTP GENERATOR ──────────────────────────────────────────────────────────

function generateTOTP(secret: string, service: string): { code: string; secondsLeft: number } | null {
  try {
    const totp = new OTPAuth.TOTP({
      issuer: service,
      label: service,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });
    const code = totp.generate();
    const secondsLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
    return { code, secondsLeft };
  } catch {
    return null;
  }
}

// ─── UI HELPERS ──────────────────────────────────────────────────────────────

function buildProgressBar(secondsLeft: number): string {
  const filled = Math.round((secondsLeft / 30) * 10);
  return '█'.repeat(filled) + '░'.repeat(10 - filled);
}

// ─── HANDLERS ────────────────────────────────────────────────────────────────

async function handleStart(db: D1Database, token: string, chatId: number, from: TelegramFrom): Promise<void> {
  const profile = await db
    .prepare('SELECT first_name FROM users WHERE user_id = ?')
    .bind(chatId)
    .first<{ first_name: string }>();

  const name = esc(profile?.first_name ?? from.first_name ?? 'there');
  const text =
    `🔐 *Welcome back, ${name}\\!*\n\n` +
    `I'm your *Edge 2FA Authenticator* — secure, instant, serverless\\.\n\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `📋 *Commands*\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `➕ \`/add <Service> <Secret>\`\n` +
    `_Add a TOTP secret key_\n\n` +
    `📋 \`/list\`\n` +
    `_View & manage your services_\n\n` +
    `ℹ️ \`/help\`\n` +
    `_Full usage guide_\n\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `🛡️ _Your secrets are stored encrypted in Cloudflare D1\\._`;

  await callTelegram(token, 'sendMessage', {
    chat_id: chatId,
    text,
    parse_mode: 'MarkdownV2',
    reply_markup: {
      inline_keyboard: [[{ text: '📋 View My Services', callback_data: 'list_services' }]],
    },
  });
}

async function handleHelp(token: string, chatId: number): Promise<void> {
  const text =
    `📖 *2FA Bot — Help Guide*\n\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `*Adding a Service*\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `\`/add Google JBSWY3DPEHPK3PXP\`\n\n` +
    `• *Service*: any name \\(e\\.g\\. Google, GitHub\\)\n` +
    `• *Secret*: your Base32 TOTP secret\n` +
    `  \\(from the QR code page, "can't scan" option\\)\n\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `*Getting a Code*\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `Use \`/list\` → tap *🔑 Get*\n\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `*Removing a Service*\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `Use \`/list\` → tap *❌* next to a service\n\n` +
    `━━━━━━━━━━━━━━━━\n` +
    `⚠️ *Important*: Delete the message containing\n` +
    `\`/add\` after use to protect your secret\\.`;

  await callTelegram(token, 'sendMessage', {
    chat_id: chatId,
    text,
    parse_mode: 'MarkdownV2',
  });
}

async function handleAdd(
  db: D1Database,
  token: string,
  chatId: number,
  messageId: number,
  serviceName: string,
  rawSecret: string
): Promise<void> {
  // Sanitize
  const service = sanitizeServiceName(serviceName);
  if (!service) {
    await sendError(token, chatId, 'Service name is invalid or empty\\.');
    return;
  }

  const secret = rawSecret.toUpperCase().replace(/\s+/g, '').replace(/-/g, '');

  if (!isValidBase32(secret)) {
    await sendError(token, chatId, 'Invalid Base32 secret\\. Check your key and try again\\.');
    return;
  }

  // Verify TOTP works
  const test = generateTOTP(secret, service);
  if (!test) {
    await sendError(token, chatId, 'Could not validate the secret\\. Please verify it\\.  ');
    return;
  }

  // Check service cap
  const { count } = await db
    .prepare('SELECT COUNT(*) as count FROM totp_secrets WHERE user_id = ?')
    .bind(chatId)
    .first<{ count: number }>() ?? { count: 0 };

  if (count >= MAX_SERVICES_PER_USER) {
    await sendError(token, chatId, `You've reached the limit of *${MAX_SERVICES_PER_USER}* services\\.`);
    return;
  }

  await db
    .prepare('INSERT OR REPLACE INTO totp_secrets (user_id, service, secret, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)')
    .bind(chatId, service, secret)
    .run();

  // Attempt to delete the /add message (contains the secret)
  await callTelegram(token, 'deleteMessage', { chat_id: chatId, message_id: messageId });

  await callTelegram(token, 'sendMessage', {
    chat_id: chatId,
    text: `✅ *${esc(service)}* has been secured\\!\n\n🗑️ _Your \\/add message was auto\\-deleted for security\\._`,
    parse_mode: 'MarkdownV2',
    reply_markup: {
      inline_keyboard: [[{ text: '📋 View My Services', callback_data: 'list_services' }]],
    },
  });
}

async function handleGetCode(
  db: D1Database,
  token: string,
  chatId: number,
  messageId: number,
  service: string
): Promise<void> {
  const record = await db
    .prepare('SELECT secret FROM totp_secrets WHERE user_id = ? AND service = ?')
    .bind(chatId, service)
    .first<{ secret: string }>();

  if (!record) {
    await callTelegram(token, 'answerCallbackQuery', {
      callback_query_id: '',
      text: 'Service not found.',
      show_alert: true,
    });
    return;
  }

  const result = generateTOTP(record.secret, service);
  if (!result) {
    await sendError(token, chatId, `Failed to generate code for *${esc(service)}*\\.`);
    return;
  }

  const { code, secondsLeft } = result;
  const bar = buildProgressBar(secondsLeft);

  const text =
    `🔐 *${esc(service)}*\n\n` +
    `\`${code}\`\n\n` +
    `⏱ \`${bar}\` ${secondsLeft}s\n` +
    `_Tap the code to copy it\\._`;

  await callTelegram(token, 'editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: 'MarkdownV2',
    reply_markup: {
      inline_keyboard: [
        [{ text: '🔄 Refresh Code', callback_data: `get:${service}` }],
        [{ text: '🔙 Back to List', callback_data: 'list_services' }],
      ],
    },
  });
}

async function handleDelete(
  db: D1Database,
  token: string,
  chatId: number,
  messageId: number,
  service: string,
  callbackId: string
): Promise<void> {
  // Show confirmation first
  await callTelegram(token, 'editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    text: `⚠️ *Delete ${esc(service)}?*\n\n_This action cannot be undone\\._`,
    parse_mode: 'MarkdownV2',
    reply_markup: {
      inline_keyboard: [
        [
          { text: '✅ Yes, Delete', callback_data: `confirm_del:${service}` },
          { text: '❌ Cancel', callback_data: 'list_services' },
        ],
      ],
    },
  });
}

async function handleConfirmDelete(
  db: D1Database,
  token: string,
  chatId: number,
  messageId: number,
  service: string
): Promise<void> {
  const result = await db
    .prepare('DELETE FROM totp_secrets WHERE user_id = ? AND service = ?')
    .bind(chatId, service)
    .run();

  if (result.meta.changes === 0) {
    await callTelegram(token, 'editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text: `⚠️ *${esc(service)}* was not found\\.`,
      parse_mode: 'MarkdownV2',
      reply_markup: { inline_keyboard: [[{ text: '🔙 Back', callback_data: 'list_services' }]] },
    });
    return;
  }

  await callTelegram(token, 'editMessageText', {
    chat_id: chatId,
    message_id: messageId,
    text: `🗑️ *${esc(service)}* has been permanently deleted\\.`,
    parse_mode: 'MarkdownV2',
    reply_markup: { inline_keyboard: [[{ text: '🔙 Back to List', callback_data: 'list_services' }]] },
  });
}

async function renderServiceList(
  db: D1Database,
  token: string,
  chatId: number,
  editMessageId?: number
): Promise<void> {
  const { results } = await db
    .prepare('SELECT service FROM totp_secrets WHERE user_id = ? ORDER BY service ASC')
    .bind(chatId)
    .all<{ service: string }>();

  if (!results || results.length === 0) {
    const text =
      `📭 *No services saved yet\\.*\n\n` +
      `Add your first with:\n` +
      `\`/add ServiceName YourBase32Secret\`\n\n` +
      `💡 _Use \`/help\` for a detailed guide\\._`;

    const payload = { chat_id: chatId, text, parse_mode: 'MarkdownV2' };
    if (editMessageId) {
      await callTelegram(token, 'editMessageText', { ...payload, message_id: editMessageId });
    } else {
      await callTelegram(token, 'sendMessage', payload);
    }
    return;
  }

  const keyboard = results.map((r) => [
    { text: `🔑 ${r.service}`, callback_data: `get:${r.service}` },
    { text: '🗑️', callback_data: `del:${r.service}` },
  ]);

  const text =
    `🗄️ *Your Secured Services* \\(${results.length}\\)\n` +
    `_Tap a service to get its current code:_`;

  const payload = {
    chat_id: chatId,
    text,
    parse_mode: 'MarkdownV2',
    reply_markup: { inline_keyboard: keyboard },
  };

  if (editMessageId) {
    await callTelegram(token, 'editMessageText', { ...payload, message_id: editMessageId });
  } else {
    await callTelegram(token, 'sendMessage', payload);
  }
}

async function sendError(token: string, chatId: number, markdownMessage: string): Promise<void> {
  await callTelegram(token, 'sendMessage', {
    chat_id: chatId,
    text: `❌ ${markdownMessage}`,
    parse_mode: 'MarkdownV2',
  });
}

// ─── WEBHOOK ROUTE ────────────────────────────────────────────────────────────

app.post('/webhook', async (c) => {
  const db = c.env.DB;
  const token = c.env.TELEGRAM_BOT_TOKEN;
  const webhookSecret = c.env.WEBHOOK_SECRET;

  // ── Security: Validate webhook secret header ──────────────────────────────
  if (!validateWebhookSecret(c.req.raw, webhookSecret)) {
    log.warn('Rejected request: invalid webhook secret');
    return c.text('Unauthorized', 401);
  }

  let update: TelegramUpdate;
  try {
    update = await c.req.json<TelegramUpdate>();
  } catch {
    log.warn('Rejected request: invalid JSON body');
    return c.text('Bad Request', 400);
  }

  // ── Respond to Telegram immediately (required within 5s) ──────────────────
  // We use c.executionCtx.waitUntil to process async after responding
  c.executionCtx.waitUntil(processUpdate(db, token, update));

  return c.text('OK', 200);
});

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

app.get('/health', (c) =>
  c.json({ status: 'ok', version: BOT_VERSION, ts: Date.now() })
);

// ─── SETUP ROUTE (call once to register webhook) ──────────────────────────────

app.get('/setup', async (c) => {
  const token = c.env.TELEGRAM_BOT_TOKEN;
  const webhookSecret = c.env.WEBHOOK_SECRET;
  const host = new URL(c.req.url).origin;
  const webhookUrl = `${host}/webhook`;

  const res = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: webhookUrl,
      secret_token: webhookSecret,
      allowed_updates: ['message', 'callback_query'],
      drop_pending_updates: true,
      max_connections: 100,
    }),
  });

  const data = await res.json();
  log.info('Webhook setup attempted', { webhookUrl, result: data });
  return c.json(data);
});

// ─── CORE UPDATE PROCESSOR ────────────────────────────────────────────────────

async function processUpdate(db: D1Database, token: string, update: TelegramUpdate): Promise<void> {
  try {
    // ── CALLBACK QUERIES (button clicks) ──
    if (update.callback_query) {
      const query = update.callback_query;
      const chatId = query.message.chat.id;
      const messageId = query.message.message_id;
      const data = query.data ?? '';

      await upsertUser(db, query.from);

      if (await isRateLimited(db, query.from.id)) {
        await callTelegram(token, 'answerCallbackQuery', {
          callback_query_id: query.id,
          text: '⏳ Slow down! Try again in a moment.',
          show_alert: true,
        });
        return;
      }

      const colonIdx = data.indexOf(':');
      const action = colonIdx === -1 ? data : data.slice(0, colonIdx);
      const service = colonIdx === -1 ? '' : data.slice(colonIdx + 1);

      log.info('Callback action', { userId: query.from.id, action, service });

      if (action === 'get') {
        await handleGetCode(db, token, chatId, messageId, service);
      } else if (action === 'del') {
        await handleDelete(db, token, chatId, messageId, service, query.id);
      } else if (action === 'confirm_del') {
        await handleConfirmDelete(db, token, chatId, messageId, service);
      } else if (action === 'list_services') {
        await renderServiceList(db, token, chatId, messageId);
      }

      // Always acknowledge the callback query
      await callTelegram(token, 'answerCallbackQuery', { callback_query_id: query.id });
      return;
    }

    // ── TEXT MESSAGES ──
    if (!update.message?.text) return;

    const msg = update.message;
    const chatId = msg.chat.id;
    const text = msg.text.trim();

    await upsertUser(db, msg.from);

    if (await isRateLimited(db, msg.from.id)) {
      await callTelegram(token, 'sendMessage', {
        chat_id: chatId,
        text: '⏳ You\'re sending too many requests\\. Please wait a moment\\.',
        parse_mode: 'MarkdownV2',
      });
      return;
    }

    // Parse command (strip bot @mention if present)
    const parts = text.split(/\s+/);
    const rawCommand = parts[0].toLowerCase();
    const command = rawCommand.includes('@') ? rawCommand.split('@')[0] : rawCommand;
    const args = parts.slice(1);

    log.info('Command received', { userId: msg.from.id, command });

    if (command === '/start') {
      await handleStart(db, token, chatId, msg.from);
    } else if (command === '/help') {
      await handleHelp(token, chatId);
    } else if (command === '/add') {
      if (args.length < 2) {
        await sendError(token, chatId, 'Usage: \`/add ServiceName Base32Secret\`');
        return;
      }
      await handleAdd(db, token, chatId, msg.message_id, args[0], args[1]);
    } else if (command === '/list' || command === '/manage') {
      await renderServiceList(db, token, chatId);
    } else if (command === '/version') {
      await callTelegram(token, 'sendMessage', {
        chat_id: chatId,
        text: `🤖 Edge 2FA Bot v${esc(BOT_VERSION)}`,
        parse_mode: 'MarkdownV2',
      });
    } else {
      // Unknown command — send gentle hint
      await callTelegram(token, 'sendMessage', {
        chat_id: chatId,
        text: `❓ Unknown command\\. Use \`/help\` to see all commands\\.`,
        parse_mode: 'MarkdownV2',
      });
    }
  } catch (err) {
    log.error('processUpdate error', { err: String(err), updateId: update.update_id });
  }
}

export default app;
