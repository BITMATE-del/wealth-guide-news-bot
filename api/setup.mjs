const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";
const SETUP_KEY = process.env.SETUP_KEY || "";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false });

  const provided = req.headers["x-setup-key"];
  if (!SETUP_KEY || provided !== SETUP_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  if (!BOT_TOKEN) {
    return res.status(500).json({ ok: false, error: "missing_bot_token" });
  }

  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const proto = req.headers["x-forwarded-proto"] || "https";
  const url = `${proto}://${host}/api/telegram`;

  const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      url,
      secret_token: WEBHOOK_SECRET || undefined,
      allowed_updates: ["message", "callback_query"]
    }),
  });

  const data = await response.json();
  return res.status(response.ok ? 200 : 500).json({ ...data, webhook: url });
}
