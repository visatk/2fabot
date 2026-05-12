import { Hono } from 'hono';
import * as OTPAuth from 'otpauth';

export type Bindings = {
	DB: D1Database;
	TELEGRAM_BOT_TOKEN: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// --- TELEGRAM API HELPERS ---

async function callTelegramAPI(token: string, method: string, payload: any) {
	const url = `https://api.telegram.org/bot${token}/${method}`;
	return fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(payload),
	});
}

function escapeMarkdown(text: string): string {
	return text.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

// --- MIDDLEWARE: USER PROFILE MANAGEMENT ---

async function upsertUserProfile(db: D1Database, from: any) {
	await db.prepare(`
		INSERT INTO users (user_id, username, first_name, last_active) 
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET 
		username = excluded.username, 
		first_name = excluded.first_name, 
		last_active = CURRENT_TIMESTAMP
	`).bind(from.id, from.username || null, from.first_name || null).run();
}

// --- MAIN WEBHOOK ROUTER ---

app.post('/webhook', async (c) => {
	const update = await c.req.json();
	const db = c.env.DB;
	const token = c.env.TELEGRAM_BOT_TOKEN;

	try {
		// 1. HANDLE INLINE BUTTON CLICKS (CALLBACK QUERIES)
		if (update.callback_query) {
			const query = update.callback_query;
			const chatId = query.message.chat.id;
			const messageId = query.message.message_id;
			const data = query.data; // e.g., "get:Google", "del:Google"
			
			await upsertUserProfile(db, query.from);

			const [action, ...serviceParts] = data.split(':');
			const service = serviceParts.join(':');

			if (action === 'get') {
				const record = await db.prepare('SELECT secret FROM totp_secrets WHERE user_id = ? AND service = ?')
					.bind(chatId, service).first<{ secret: string }>();

				if (record) {
					const totp = new OTPAuth.TOTP({
						issuer: service,
						label: '2FABot',
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(record.secret)
					});
					
					const code = totp.generate();
					const text = `🔐 *${escapeMarkdown(service)}* 2FA Code:\n\n\`${code}\`\n\n_Tap the code to copy\\. Valid for 30s\\._`;
					
					// Update the message with the code and a "Back to List" button
					await callTelegramAPI(token, 'editMessageText', {
						chat_id: chatId,
						message_id: messageId,
						text: text,
						parse_mode: 'MarkdownV2',
						reply_markup: {
							inline_keyboard: [[{ text: '🔙 Back to List', callback_data: 'list_services' }]]
						}
					});
				}
			} else if (action === 'del') {
				await db.prepare('DELETE FROM totp_secrets WHERE user_id = ? AND service = ?')
					.bind(chatId, service).run();

				await callTelegramAPI(token, 'editMessageText', {
					chat_id: chatId,
					message_id: messageId,
					text: `🗑️ Service *${escapeMarkdown(service)}* has been securely deleted\\.`,
					parse_mode: 'MarkdownV2',
					reply_markup: {
						inline_keyboard: [[{ text: '🔙 Back to List', callback_data: 'list_services' }]]
					}
				});
			} else if (action === 'list_services') {
				// Re-render the list view
				await renderServiceList(db, token, chatId, messageId);
			}

			// Acknowledge the callback to remove the loading state on the user's client
			await callTelegramAPI(token, 'answerCallbackQuery', { callback_query_id: query.id });
			return c.text('OK');
		}

		// 2. HANDLE STANDARD TEXT MESSAGES
		if (update.message && update.message.text) {
			const chatId = update.message.chat.id;
			const text = update.message.text.trim();
			
			await upsertUserProfile(db, update.message.from);

			const args = text.split(' ');
			const command = args[0].toLowerCase();

			if (command === '/start') {
				const profile = await db.prepare('SELECT first_name FROM users WHERE user_id = ?').bind(chatId).first<{ first_name: string }>();
				const welcome = `*Welcome, ${escapeMarkdown(profile?.first_name || 'User')}!* 🛡️\n\n` +
					`I am your secure Edge 2FA Authenticator\\.\n\n` +
					`*To add a service:*\n\`/add <Service> <SecretKey>\`\n\n` +
					`*To view/manage codes:*\nSend \`/list\` or use the menu\\.`;
				
				await callTelegramAPI(token, 'sendMessage', {
					chat_id: chatId,
					text: welcome,
					parse_mode: 'MarkdownV2'
				});
			} 
			else if (command === '/add' && args.length >= 3) {
				const service = args[1];
				const secret = args[2].toUpperCase().replace(/\s+/g, '');
				
				try {
					new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret) });
				} catch (e) {
					await callTelegramAPI(token, 'sendMessage', {
						chat_id: chatId,
						text: `❌ *Invalid Base32 secret*\\.`,
						parse_mode: 'MarkdownV2'
					});
					return c.text('OK');
				}

				await db.prepare('INSERT OR REPLACE INTO totp_secrets (user_id, service, secret) VALUES (?, ?, ?)')
					.bind(chatId, service, secret).run();
					
				await callTelegramAPI(token, 'sendMessage', {
					chat_id: chatId,
					text: `✅ *${escapeMarkdown(service)}* secured\\.\nUse \`/list\` to view it\\.`,
					parse_mode: 'MarkdownV2'
				});
			} 
			else if (command === '/list' || command === '/manage') {
				await renderServiceList(db, token, chatId);
			}
		}
	} catch (err) {
		console.error('Bot Error:', err);
	}

	return c.text('OK');
});

// --- UI GENERATOR ---

async function renderServiceList(db: D1Database, token: string, chatId: number, editMessageId?: number) {
	const { results } = await db.prepare('SELECT service FROM totp_secrets WHERE user_id = ?').bind(chatId).all<{ service: string }>();

	if (!results || results.length === 0) {
		const text = `📭 You have no 2FA services saved\\.\nUse \`/add <Service> <Secret>\` to add one\\.`;
		if (editMessageId) {
			await callTelegramAPI(token, 'editMessageText', { chat_id: chatId, message_id: editMessageId, text, parse_mode: 'MarkdownV2' });
		} else {
			await callTelegramAPI(token, 'sendMessage', { chat_id: chatId, text, parse_mode: 'MarkdownV2' });
		}
		return;
	}

	// Build Inline Keyboard UI
	const keyboard = results.map(r => {
		return [
			{ text: `🔑 Get ${r.service}`, callback_data: `get:${r.service}` },
			{ text: `❌`, callback_data: `del:${r.service}` }
		];
	});

	const text = `🗄️ *Your Secured Services*\n_Select a service to generate a code:_`;
	const payload = {
		chat_id: chatId,
		text: text,
		parse_mode: 'MarkdownV2',
		reply_markup: { inline_keyboard: keyboard }
	};

	if (editMessageId) {
		await callTelegramAPI(token, 'editMessageText', { ...payload, message_id: editMessageId });
	} else {
		await callTelegramAPI(token, 'sendMessage', payload);
	}
}

export default app;
