import { Hono } from 'hono';
import * as OTPAuth from 'otpauth';

// ─── TYPES & BINDINGS ────────────────────────────────────────────────────────

export type Bindings = {
	DB: D1Database;
	TELEGRAM_BOT_TOKEN: string;
	WEBHOOK_SECRET: string; // Set via: wrangler secret put WEBHOOK_SECRET
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

// ─── SYSTEM CONSTANTS ────────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 25; // Adjusted for better UX during rapid usage
const MAX_SERVICE_NAME_LENGTH = 40; // UX: Keep it clean on mobile
const MAX_SERVICES_PER_USER = 50;
const BOT_VERSION = '2.1.0-edge';

// ─── APP INSTANCE ────────────────────────────────────────────────────────────

const app = new Hono<{ Bindings: Bindings }>();

// ─── TELEMETRY & LOGGING ─────────────────────────────────────────────────────

const log = {
	info: (msg: string, meta?: Record<string, unknown>) => console.log(JSON.stringify({ level: 'INFO', msg, ...meta, ts: Date.now() })),
	warn: (msg: string, meta?: Record<string, unknown>) => console.warn(JSON.stringify({ level: 'WARN', msg, ...meta, ts: Date.now() })),
	error: (msg: string, meta?: Record<string, unknown>) => console.error(JSON.stringify({ level: 'ERROR', msg, ...meta, ts: Date.now() })),
};

async function logTelemetry(db: D1Database, userId: number, action: string, service?: string): Promise<void> {
	try {
		await db
			.prepare('INSERT INTO event_log (user_id, action, service) VALUES (?, ?, ?)')
			.bind(userId, action, service ?? null)
			.run();
	} catch (err) {
		log.error('Telemetry insertion failed', { err: String(err), action, userId });
	}
}

// ─── TELEGRAM API ADAPTER ────────────────────────────────────────────────────

async function callTelegram(token: string, method: string, payload: Record<string, unknown>): Promise<boolean> {
	try {
		const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
		});

		if (!res.ok) {
			const body = await res.text();
			log.error(`Telegram API Exception [${method}]`, { status: res.status, body });
			return false;
		}
		return true;
	} catch (err) {
		log.error(`Telegram API Fatal [${method}]`, { err: String(err) });
		return false;
	}
}

// MarkdownV2 Strict Escaper (Prevents layout breakage)
function esc(text: string): string {
	return String(text).replace(/[_*[\]()~`>#+\-=|{}.!\\]/g, '\\$&');
}

// ─── CORE SECURITY ARCHITECTURE ──────────────────────────────────────────────

function validateWebhookSecret(request: Request, secret: string): boolean {
	const header = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
	if (!header || !secret || header.length !== secret.length) return false;

	// Constant-time bitwise comparison
	let diff = 0;
	for (let i = 0; i < header.length; i++) {
		diff |= header.charCodeAt(i) ^ secret.charCodeAt(i);
	}
	return diff === 0;
}

function isValidBase32(secret: string): boolean {
	// Strict RFC 4648 Base32 validation
	return /^[A-Z2-7]+=*$/.test(secret) && secret.replace(/=/g, '').length >= 8;
}

function sanitizeServiceName(name: string): string {
	return name
		.replace(/[^a-zA-Z0-9 _\-\.@]/g, '')
		.trim()
		.slice(0, MAX_SERVICE_NAME_LENGTH);
}

// ─── D1 STATE MANAGEMENT ─────────────────────────────────────────────────────

async function isRateLimited(db: D1Database, userId: number): Promise<boolean> {
	try {
		const record = await db
			.prepare('SELECT count, window_start FROM rate_limits WHERE user_id = ?')
			.bind(userId)
			.first<RateLimitRecord>();

		const now = Date.now();

		if (!record || now - record.window_start > RATE_LIMIT_WINDOW_MS) {
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
			log.warn('Rate limit exceeded', { userId });
			return true;
		}

		await db.prepare('UPDATE rate_limits SET count = count + 1 WHERE user_id = ?').bind(userId).run();
		return false;
	} catch {
		// Fail-open infrastructure design
		return false;
	}
}

async function upsertUser(db: D1Database, from: TelegramFrom): Promise<void> {
	await db
		.prepare(`
			INSERT INTO users (user_id, username, first_name, last_active)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(user_id) DO UPDATE SET
				username    = excluded.username,
				first_name  = excluded.first_name,
				last_active = CURRENT_TIMESTAMP
		`)
		.bind(from.id, from.username ?? null, from.first_name ?? null)
		.run();
}

// ─── CRYPTOGRAPHIC TOTP ENGINE ───────────────────────────────────────────────

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
	} catch (err) {
		log.error('TOTP Generation Failed', { err: String(err), service });
		return null;
	}
}

// Visual UX Element
function buildProgressBar(secondsLeft: number): string {
	const filled = Math.round((secondsLeft / 30) * 10);
	return '■'.repeat(filled) + '□'.repeat(10 - filled);
}

// ─── COMMAND HANDLERS (CONTROLLERS) ──────────────────────────────────────────

async function handleStart(db: D1Database, token: string, chatId: number, from: TelegramFrom): Promise<void> {
	const name = esc(from.first_name ?? 'there');
	const text =
		`🔐 *Welcome, ${name}\\!*\n\n` +
		`I'm your **Secure 2FA Authenticator**\\.\n` +
		`Fast, serverless, and completely private\\.\n\n` +
		`━━━━━━━━━━━━━━━━\n` +
		`➕ \`/add <Service> <Secret>\`\n` +
		`_Adds a new TOTP secret key_\n\n` +
		`📋 \`/list\`\n` +
		`_Manage your secured services_\n\n` +
		`ℹ️ \`/help\`\n` +
		`_View detailed instructions_\n` +
		`━━━━━━━━━━━━━━━━\n\n` +
		`🛡️ _Your keys are encrypted\\._`;

	await callTelegram(token, 'sendMessage', {
		chat_id: chatId,
		text,
		parse_mode: 'MarkdownV2',
		reply_markup: {
			inline_keyboard: [[{ text: '🛡️ Access My Vault', callback_data: 'list_services' }]],
		},
	});
}

async function handleHelp(token: string, chatId: number): Promise<void> {
	const text =
		`📖 *Secure Vault Guide*\n\n` +
		`*1\\. Adding a Key*\n` +
		`\`/add Google JBSWY3DPEHPK3PXP\`\n` +
		`_Provides the service name and the Base32 secret from the setup screen\\._\n\n` +
		`*2\\. Generating a Code*\n` +
		`Type \`/list\` and tap the service name\\. You can tap the generated code to copy it instantly\\.\n\n` +
		`*3\\. Security Note*\n` +
		`Messages containing \`/add\` are automatically deleted by the bot to prevent keys from remaining in your chat history\\.`;

	await callTelegram(token, 'sendMessage', { chat_id: chatId, text, parse_mode: 'MarkdownV2' });
}

async function handleAdd(
	db: D1Database,
	token: string,
	chatId: number,
	messageId: number,
	serviceName: string,
	rawSecret: string
): Promise<void> {
	const service = sanitizeServiceName(serviceName);
	if (!service) {
		await sendError(token, chatId, 'Invalid service name format\\.');
		return;
	}

	const secret = rawSecret.toUpperCase().replace(/\s+/g, '').replace(/-/g, '');
	if (!isValidBase32(secret)) {
		await sendError(token, chatId, 'Invalid Base32 secret\\. Please check the string and try again\\.');
		return;
	}

	const test = generateTOTP(secret, service);
	if (!test) {
		await sendError(token, chatId, 'Key validation failed\\. The secret is corrupted\\.');
		return;
	}

	const { count } = (await db.prepare('SELECT COUNT(*) as count FROM totp_secrets WHERE user_id = ?').bind(chatId).first<{ count: number }>()) ?? {
		count: 0,
	};

	if (count >= MAX_SERVICES_PER_USER) {
		await sendError(token, chatId, `Vault limit reached \\(${MAX_SERVICES_PER_USER} services\\)\\.`);
		return;
	}

	await db
		.prepare('INSERT OR REPLACE INTO totp_secrets (user_id, service, secret, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)')
		.bind(chatId, service, secret)
		.run();

	// Auto-delete the sensitive input message
	await callTelegram(token, 'deleteMessage', { chat_id: chatId, message_id: messageId });

	await callTelegram(token, 'sendMessage', {
		chat_id: chatId,
		text: `✅ *${esc(service)}* secured in your vault\\!\n\n🗑️ _Message auto\\-deleted for security\\._`,
		parse_mode: 'MarkdownV2',
		reply_markup: {
			inline_keyboard: [[{ text: '📋 View Vault', callback_data: 'list_services' }]],
		},
	});
}

async function handleGetCode(db: D1Database, token: string, chatId: number, messageId: number, service: string): Promise<void> {
	const record = await db.prepare('SELECT secret FROM totp_secrets WHERE user_id = ? AND service = ?').bind(chatId, service).first<{ secret: string }>();

	if (!record) {
		await callTelegram(token, 'answerCallbackQuery', { callback_query_id: '', text: 'Service not found.', show_alert: true });
		return;
	}

	const result = generateTOTP(record.secret, service);
	if (!result) {
		await sendError(token, chatId, `Generation failed for *${esc(service)}*\\.`);
		return;
	}

	const { code, secondsLeft } = result;
	const bar = buildProgressBar(secondsLeft);

	const text = `🔐 *${esc(service)}*\n\n` + `\`${code}\`\n\n` + `⏱ \`${bar}\` *${secondsLeft}s*\n` + `_Tap code to copy_`;

	await callTelegram(token, 'editMessageText', {
		chat_id: chatId,
		message_id: messageId,
		text,
		parse_mode: 'MarkdownV2',
		reply_markup: {
			inline_keyboard: [
				[{ text: '🔄 Refresh Token', callback_data: `get:${service}` }],
				[{ text: '🔙 Back to Vault', callback_data: 'list_services' }],
			],
		},
	});
}

async function handleDelete(db: D1Database, token: string, chatId: number, messageId: number, service: string): Promise<void> {
	await callTelegram(token, 'editMessageText', {
		chat_id: chatId,
		message_id: messageId,
		text: `⚠️ *Are you sure?*\n\nDelete *${esc(service)}* from your vault? This is irreversible\\.`,
		parse_mode: 'MarkdownV2',
		reply_markup: {
			inline_keyboard: [
				[
					{ text: '🚨 Yes, Delete', callback_data: `confirm_del:${service}` },
					{ text: '❌ Cancel', callback_data: 'list_services' },
				],
			],
		},
	});
}

async function handleConfirmDelete(db: D1Database, token: string, chatId: number, messageId: number, service: string): Promise<void> {
	const result = await db.prepare('DELETE FROM totp_secrets WHERE user_id = ? AND service = ?').bind(chatId, service).run();

	if (result.meta.changes === 0) {
		await callTelegram(token, 'editMessageText', {
			chat_id: chatId,
			message_id: messageId,
			text: `⚠️ *${esc(service)}* not found in vault\\.`,
			parse_mode: 'MarkdownV2',
			reply_markup: { inline_keyboard: [[{ text: '🔙 Back', callback_data: 'list_services' }]] },
		});
		return;
	}

	await callTelegram(token, 'editMessageText', {
		chat_id: chatId,
		message_id: messageId,
		text: `🗑️ *${esc(service)}* permanently wiped\\.`,
		parse_mode: 'MarkdownV2',
		reply_markup: { inline_keyboard: [[{ text: '🔙 Back to Vault', callback_data: 'list_services' }]] },
	});
}

async function renderServiceList(db: D1Database, token: string, chatId: number, editMessageId?: number): Promise<void> {
	const { results } = await db.prepare('SELECT service FROM totp_secrets WHERE user_id = ? ORDER BY service ASC').bind(chatId).all<{ service: string }>();

	if (!results || results.length === 0) {
		const text = `📭 *Vault is empty\\.*\n\nSecure your first service using:\n\`/add <Service> <Secret>\``;
		const payload = { chat_id: chatId, text, parse_mode: 'MarkdownV2' };
		editMessageId ? await callTelegram(token, 'editMessageText', { ...payload, message_id: editMessageId }) : await callTelegram(token, 'sendMessage', payload);
		return;
	}

	// Layout UX: Group items nicely
	const keyboard = results.map((r) => [
		{ text: `🔑 ${r.service}`, callback_data: `get:${r.service}` },
		{ text: '🗑️', callback_data: `del:${r.service}` },
	]);

	const text = `🗄️ *Your Secure Vault* \\(${results.length}\\)\n\n_Select an issuer to generate a token:_`;

	const payload = {
		chat_id: chatId,
		text,
		parse_mode: 'MarkdownV2',
		reply_markup: { inline_keyboard: keyboard },
	};

	editMessageId ? await callTelegram(token, 'editMessageText', { ...payload, message_id: editMessageId }) : await callTelegram(token, 'sendMessage', payload);
}

async function sendError(token: string, chatId: number, markdownMessage: string): Promise<void> {
	await callTelegram(token, 'sendMessage', {
		chat_id: chatId,
		text: `❌ ${markdownMessage}`,
		parse_mode: 'MarkdownV2',
	});
}

// ─── ROUTING INTERFACE ───────────────────────────────────────────────────────

app.post('/webhook', async (c) => {
	const db = c.env.DB;
	const token = c.env.TELEGRAM_BOT_TOKEN;
	const webhookSecret = c.env.WEBHOOK_SECRET;

	// Edge-layer Authentication
	if (!validateWebhookSecret(c.req.raw, webhookSecret)) {
		log.warn('Unauthorized Access Attempt');
		return c.text('Unauthorized', 401);
	}

	let update: TelegramUpdate;
	try {
		update = await c.req.json<TelegramUpdate>();
	} catch {
		return c.text('Bad Request', 400);
	}

	// Utilize executionCtx for zero-latency background processing
	c.executionCtx.waitUntil(processUpdate(c.executionCtx, db, token, update));

	return c.text('OK', 200);
});

app.get('/health', (c) => c.json({ status: 'ok', version: BOT_VERSION, ts: Date.now(), region: c.req.raw.cf?.colo || 'DEV' }));

app.get('/setup', async (c) => {
	const token = c.env.TELEGRAM_BOT_TOKEN;
	const webhookUrl = `${new URL(c.req.url).origin}/webhook`;

	const res = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			url: webhookUrl,
			secret_token: c.env.WEBHOOK_SECRET,
			allowed_updates: ['message', 'callback_query'],
			drop_pending_updates: true,
		}),
	});

	return c.json(await res.json());
});

// ─── CENTRAL UPDATE PROCESSOR ────────────────────────────────────────────────

async function processUpdate(ctx: ExecutionContext, db: D1Database, token: string, update: TelegramUpdate): Promise<void> {
	try {
		// 1. Handle UI Button Callbacks
		if (update.callback_query) {
			const query = update.callback_query;
			const { id: chatId } = query.message.chat;
			const messageId = query.message.message_id;
			const data = query.data ?? '';

			await upsertUser(db, query.from);

			if (await isRateLimited(db, query.from.id)) {
				await callTelegram(token, 'answerCallbackQuery', { callback_query_id: query.id, text: '⏳ Too many requests. Cool down.', show_alert: true });
				return;
			}

			const colonIdx = data.indexOf(':');
			const action = colonIdx === -1 ? data : data.slice(0, colonIdx);
			const service = colonIdx === -1 ? '' : data.slice(colonIdx + 1);

			// Background Telemetry
			ctx.waitUntil(logTelemetry(db, query.from.id, `btn_${action}`, service));

			switch (action) {
				case 'get':
					await handleGetCode(db, token, chatId, messageId, service);
					break;
				case 'del':
					await handleDelete(db, token, chatId, messageId, service);
					break;
				case 'confirm_del':
					await handleConfirmDelete(db, token, chatId, messageId, service);
					break;
				case 'list_services':
					await renderServiceList(db, token, chatId, messageId);
					break;
			}

			await callTelegram(token, 'answerCallbackQuery', { callback_query_id: query.id });
			return;
		}

		// 2. Handle Text Commands
		if (!update.message?.text) return;
		const msg = update.message;
		const chatId = msg.chat.id;
		const text = msg.text.trim();

		await upsertUser(db, msg.from);

		if (await isRateLimited(db, msg.from.id)) {
			await callTelegram(token, 'sendMessage', { chat_id: chatId, text: '⏳ Rate limit exceeded\\. Please wait a moment\\.', parse_mode: 'MarkdownV2' });
			return;
		}

		const parts = text.split(/\s+/);
		const rawCommand = parts[0].toLowerCase();
		const command = rawCommand.includes('@') ? rawCommand.split('@')[0] : rawCommand;
		const args = parts.slice(1);

		// Background Telemetry
		ctx.waitUntil(logTelemetry(db, msg.from.id, `cmd_${command.substring(1)}`));

		switch (command) {
			case '/start':
				await handleStart(db, token, chatId, msg.from);
				break;
			case '/help':
				await handleHelp(token, chatId);
				break;
			case '/add':
				if (args.length < 2) {
					await sendError(token, chatId, 'Format required: \`/add <ServiceName> <Base32Secret>\`');
					return;
				}
				await handleAdd(db, token, chatId, msg.message_id, args[0], args[1]);
				break;
			case '/list':
			case '/manage':
				await renderServiceList(db, token, chatId);
				break;
			case '/version':
				await callTelegram(token, 'sendMessage', { chat_id: chatId, text: `🤖 **Edge 2FA Bot** v${esc(BOT_VERSION)}`, parse_mode: 'MarkdownV2' });
				break;
			default:
				await callTelegram(token, 'sendMessage', { chat_id: chatId, text: `❓ Unknown command\\. Use \`/help\` for the guide\\.`, parse_mode: 'MarkdownV2' });
		}
	} catch (err) {
		log.error('Processor Fault', { err: String(err), updateId: update.update_id });
	}
}

export default app;
