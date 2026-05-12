import { Hono } from 'hono';
import * as OTPAuth from 'otpauth';

// 1. Define our Runtime Bindings
export type Bindings = {
	DB: D1Database;
	TELEGRAM_BOT_TOKEN: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Helper: Securely send messages via Telegram API
async function sendTelegramMessage(token: string, chatId: number, text: string) {
	const url = `https://api.telegram.org/bot${token}/sendMessage`;
	await fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			chat_id: chatId,
			text: text,
			parse_mode: 'MarkdownV2',
		}),
	});
}

// Helper: Escape MarkdownV2 special characters
function escapeMarkdown(text: string): string {
	return text.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

// 2. Main Webhook Handler
app.post('/webhook', async (c) => {
	const update = await c.req.json();

	// Ignore non-message updates to save compute cycles
	if (!update.message || !update.message.text) return c.text('OK');

	const chatId = update.message.chat.id;
	const text = update.message.text.trim();
	const db = c.env.DB;
	const token = c.env.TELEGRAM_BOT_TOKEN;

	const args = text.split(' ');
	const command = args[0].toLowerCase();

	try {
		// --- COMMAND: /start ---
		if (command === '/start') {
			const welcome = `*Welcome to Edge 2FA Bot* 🚀\n\n` +
				`Commands:\n` +
				`\`/add <service> <base32_secret>\` \\- Add a new 2FA code\n` +
				`\`/get <service>\` \\- Get the current TOTP code\n` +
				`\`/list\` \\- List all your saved services\n` +
				`\`/delete <service>\` \\- Remove a service`;
			await sendTelegramMessage(token, chatId, welcome);
		} 
		
		// --- COMMAND: /add ---
		else if (command === '/add' && args.length >= 3) {
			const service = args[1];
			// Clean up secret (remove spaces, standardize case)
			const secret = args[2].toUpperCase().replace(/\s+/g, '');
			
			// Validate the Base32 secret before saving
			try {
				new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret) });
			} catch (e) {
				await sendTelegramMessage(token, chatId, `❌ *Invalid Base32 secret*\\. Please check your key\\.`);
				return c.text('OK');
			}

			// Upsert into D1 Database
			await db.prepare('INSERT OR REPLACE INTO totp_secrets (user_id, service, secret) VALUES (?, ?, ?)')
				.bind(chatId, service, secret)
				.run();
				
			await sendTelegramMessage(token, chatId, `✅ Service *${escapeMarkdown(service)}* added successfully\\!`);
		} 
		
		// --- COMMAND: /get ---
		else if (command === '/get' && args.length === 2) {
			const service = args[1];
			
			const record = await db.prepare('SELECT secret FROM totp_secrets WHERE user_id = ? AND service = ?')
				.bind(chatId, service)
				.first<{ secret: string }>();

			if (!record) {
				await sendTelegramMessage(token, chatId, `❌ Service *${escapeMarkdown(service)}* not found\\.`);
				return c.text('OK');
			}

			// Generate TOTP on the Edge
			const totp = new OTPAuth.TOTP({
				issuer: service,
				label: '2FABot',
				algorithm: 'SHA1',
				digits: 6,
				period: 30,
				secret: OTPAuth.Secret.fromBase32(record.secret)
			});
			
			const code = totp.generate();
			
			// Formatted in monospace `code` for one-tap copying in Telegram UI
			await sendTelegramMessage(token, chatId, `🔐 *${escapeMarkdown(service)}*:\n\n\`${code}\``);
		} 
		
		// --- COMMAND: /list ---
		else if (command === '/list') {
			const { results } = await db.prepare('SELECT service FROM totp_secrets WHERE user_id = ?')
				.bind(chatId)
				.all<{ service: string }>();

			if (!results || results.length === 0) {
				await sendTelegramMessage(token, chatId, `You have no saved services\\.`);
			} else {
				const services = results.map(r => `\\- \`${escapeMarkdown(r.service)}\``).join('\n');
				await sendTelegramMessage(token, chatId, `📋 *Your Services:*\n${services}`);
			}
		} 
		
		// --- COMMAND: /delete ---
		else if (command === '/delete' && args.length === 2) {
			const service = args[1];
			await db.prepare('DELETE FROM totp_secrets WHERE user_id = ? AND service = ?')
				.bind(chatId, service)
				.run();
			await sendTelegramMessage(token, chatId, `🗑️ Service *${escapeMarkdown(service)}* deleted\\.`);
		} 
		
		// --- FALLBACK ---
		else {
			await sendTelegramMessage(token, chatId, `Unknown command\\. Use \`/start\` to see instructions\\.`);
		}
	} catch (err) {
		console.error('Edge Execution Error:', err);
		await sendTelegramMessage(token, chatId, `⚠️ *An internal edge error occurred*\\.`);
	}

	// Always return 200 OK so Telegram doesn't retry the webhook delivery
	return c.text('OK');
});

export default app;
