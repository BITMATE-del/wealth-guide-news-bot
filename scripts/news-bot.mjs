import fs from "node:fs/promises";
import crypto from "node:crypto";
import { XMLParser } from "fast-xml-parser";

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const DRY_RUN = process.env.DRY_RUN === "1";
const THRESHOLD = Number(process.env.IMPORTANCE_THRESHOLD || 7);
const MAX_ALERTS = Number(process.env.MAX_ALERTS_PER_RUN || 4);
const STATE_PATH = new URL("../state/news-state.json", import.meta.url);

const GOOGLE_NEWS_QUERIES = [
  { q: "Federal Reserve OR FOMC interest rate inflation CPI PCE jobs", label: "글로벌 경제" },
  { q: "Bank of Korea interest rate inflation won exchange rate Korea economy", label: "한국 경제" },
  { q: "Nasdaq S&P 500 Dow futures market crash rally volatility", label: "미국 증시" },
  { q: "KOSPI KOSDAQ Samsung SK Hynix market", label: "국내 증시" },
  { q: "Bitcoin Ethereum ETF SEC crypto regulation exchange hack liquidation", label: "코인" },
  { q: "oil gold bond yield dollar index geopolitical sanctions", label: "글로벌 시장" },
  { q: "Nvidia Apple Microsoft Tesla earnings guidance merger acquisition", label: "기업" }
];

const DIRECT_FEEDS = [
  { url: "https://www.coindesk.com/arc/outboundfeeds/rss/", label: "코인" },
  { url: "https://cointelegraph.com/rss", label: "코인" }
];

const WEIGHTS = [
  [/(rate cut|rate hike|interest rate|기준금리|금리 인하|금리 인상|fomc|federal reserve|연준|bank of korea|한국은행)/i, 5],
  [/(cpi|pce|inflation|소비자물가|물가|jobs report|nonfarm|고용|unemployment|실업률|gdp)/i, 4],
  [/(emergency|긴급|surprise|unexpected|예상 밖|전격|halt|trading halt|거래 중단|default|bankruptcy|파산)/i, 4],
  [/(sec|etf|regulation|ban|approval|lawsuit|규제|승인|금지|제재)/i, 3],
  [/(hack|exploit|breach|해킹|탈취|보안 사고|liquidation|청산|depeg|디페깅)/i, 5],
  [/(war|attack|missile|ceasefire|sanction|전쟁|공격|미사일|휴전|제재)/i, 4],
  [/(earnings|guidance|실적|가이던스|merger|acquisition|m&a|인수|합병)/i, 2],
  [/(nasdaq|s&p|dow|kospi|kosdaq|나스닥|코스피|코스닥|bitcoin|btc|ethereum|eth|비트코인|이더리움)/i, 2],
  [/(plunge|surge|soar|tumble|crash|급락|급등|폭락|폭등|사상 최고|record high)/i, 3],
  [/(treasury yield|bond yield|dollar index|환율|원달러|국채금리|채권금리|유가|oil|gold|금값)/i, 2]
];

const NOISE = [
  /price prediction/i,
  /presale/i,
  /airdrop/i,
  /sponsored/i,
  /opinion/i,
  /how to buy/i,
  /가격 전망/i,
  /에어드롭/i
];

function googleRssUrl(query) {
  const q = encodeURIComponent(query);
  return `https://news.google.com/rss/search?q=${q}&hl=ko&gl=KR&ceid=KR:ko`;
}

function asArray(v) {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

function cleanText(v = "") {
  return String(v)
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeTitle(title) {
  return cleanText(title)
    .replace(/\s+-\s+[^-]{2,40}$/u, "")
    .replace(/[“”"'‘’]/g, "")
    .toLowerCase();
}

function idFor(item) {
  return crypto
    .createHash("sha256")
    .update(normalizeTitle(item.title) + "|" + (item.link || ""))
    .digest("hex")
    .slice(0, 24);
}

function score(item) {
  const text = `${item.title} ${item.description}`;
  if (NOISE.some((r) => r.test(text))) return -99;
  let value = 0;
  for (const [re, weight] of WEIGHTS) {
    if (re.test(text)) value += weight;
  }
  const ageMs = Date.now() - new Date(item.pubDate || 0).getTime();
  if (Number.isFinite(ageMs) && ageMs >= 0 && ageMs <= 60 * 60 * 1000) value += 1;
  return value;
}

function classify(item) {
  const t = `${item.title} ${item.description}`;
  const tags = [];
  if (/(bitcoin|btc|ethereum|eth|crypto|코인|비트코인|이더리움|거래소|stablecoin|스테이블)/i.test(t)) tags.push("코인");
  if (/(nasdaq|s&p|dow|stock|equity|kospi|kosdaq|주식|증시|코스피|코스닥|earnings|실적)/i.test(t)) tags.push("주식");
  if (/(rate|inflation|cpi|pce|gdp|jobs|yield|dollar|economy|금리|물가|고용|환율|경제|채권)/i.test(t)) tags.push("경제");
  return tags.length ? [...new Set(tags)].join(" · ") : item.label || "시장";
}

function impactHint(item) {
  const t = `${item.title} ${item.description}`;
  if (/(rate hike|금리 인상|inflation.*(higher|rise)|물가.*상승)/i.test(t)) return "금리·채권·달러와 위험자산 변동성 확대 여부를 확인하세요.";
  if (/(rate cut|금리 인하)/i.test(t)) return "채권금리·달러·성장주·가상자산의 동반 반응을 확인하세요.";
  if (/(hack|exploit|해킹|탈취|depeg|디페깅)/i.test(t)) return "관련 거래소·토큰의 입출금 상태와 시장 유동성을 우선 확인하세요.";
  if (/(war|attack|missile|sanction|전쟁|공격|제재)/i.test(t)) return "유가·금·달러·주가지수 선물의 단기 변동성을 확인하세요.";
  if (/(earnings|guidance|실적|가이던스)/i.test(t)) return "시간외·선물 반응과 동종 업종으로의 영향 확산 여부를 확인하세요.";
  return "주요 지수·환율·채권금리·BTC의 동시 반응을 확인하세요.";
}

async function fetchFeed(url, label) {
  const res = await fetch(url, {
    headers: { "user-agent": "WealthGuideNewsBot/1.0" },
    signal: AbortSignal.timeout(12000)
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const xml = await res.text();
  const parser = new XMLParser({ ignoreAttributes: false });
  const parsed = parser.parse(xml);
  const rssItems = asArray(parsed?.rss?.channel?.item);
  const atomItems = asArray(parsed?.feed?.entry);
  const rawItems = rssItems.length ? rssItems : atomItems;
  return rawItems.map((x) => ({
    title: cleanText(x.title?.["#text"] || x.title || ""),
    link: typeof x.link === "string" ? x.link : (x.link?.["@_href"] || x.guid || ""),
    description: cleanText(x.description || x.summary || x.content || ""),
    pubDate: x.pubDate || x.published || x.updated || new Date().toISOString(),
    source: cleanText(x.source?.["#text"] || x.source || ""),
    label
  })).filter((x) => x.title && x.link);
}

async function loadState() {
  try {
    return JSON.parse(await fs.readFile(STATE_PATH, "utf8"));
  } catch {
    return { sentIds: [], updatedAt: null };
  }
}

async function saveState(state) {
  state.sentIds = state.sentIds.slice(-700);
  state.updatedAt = new Date().toISOString();
  await fs.writeFile(STATE_PATH, JSON.stringify(state, null, 2) + "\n", "utf8");
}

function escapeHtml(s = "") {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function truncate(s, n = 280) {
  const v = cleanText(s);
  return v.length > n ? v.slice(0, n - 1) + "…" : v;
}

function buildMessage(item, points) {
  const importance = points >= 11 ? "매우 높음" : "높음";
  const area = classify(item);
  const description = truncate(item.description || "세부 내용은 원문에서 확인할 수 있습니다.", 250);
  return [
    "🚨 <b>부의 길잡이 | 주요 시장속보</b>",
    "",
    `<b>[${importance}] ${escapeHtml(item.title)}</b>`,
    "",
    escapeHtml(description),
    "",
    `<b>영향 영역</b>  ${escapeHtml(area)}`,
    `<b>체크포인트</b>  ${escapeHtml(impactHint(item))}`,
    "",
    `<a href="${escapeHtml(item.link)}">원문 확인</a>`,
    "",
    "🧭 <b>부의 길잡이</b>",
    "<i>부의 방향을 찾다</i>",
    "",
    "※ 시장 영향에 대한 문구는 공개 뉴스 기반 참고용 분석이며 투자 권유가 아닙니다."
  ].join("\n");
}

async function sendTelegram(message) {
  if (DRY_RUN) {
    console.log("\n--- DRY RUN ---\n" + message);
    return;
  }
  if (!BOT_TOKEN || !CHAT_ID) {
    throw new Error("TELEGRAM_BOT_TOKEN 또는 TELEGRAM_CHAT_ID가 설정되지 않았습니다.");
  }
  const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: CHAT_ID,
      text: message,
      parse_mode: "HTML",
      disable_web_page_preview: false
    }),
    signal: AbortSignal.timeout(12000)
  });
  const data = await res.json();
  if (!data.ok) throw new Error(`Telegram API error: ${JSON.stringify(data)}`);
}

async function main() {
  const state = await loadState();
  const sent = new Set(state.sentIds || []);
  const feeds = [
    ...GOOGLE_NEWS_QUERIES.map((x) => ({ url: googleRssUrl(x.q), label: x.label })),
    ...DIRECT_FEEDS
  ];

  const results = await Promise.allSettled(feeds.map((f) => fetchFeed(f.url, f.label)));
  const items = [];
  for (const r of results) {
    if (r.status === "fulfilled") items.push(...r.value);
    else console.warn("Feed error:", r.reason?.message || r.reason);
  }

  const cutoff = Date.now() - 6 * 60 * 60 * 1000;
  const candidates = items
    .map((item) => ({ ...item, id: idFor(item), points: score(item) }))
    .filter((item) => !sent.has(item.id))
    .filter((item) => item.points >= THRESHOLD)
    .filter((item) => {
      const t = new Date(item.pubDate).getTime();
      return !Number.isFinite(t) || t >= cutoff;
    })
    .sort((a, b) => b.points - a.points || new Date(b.pubDate) - new Date(a.pubDate));

  const chosen = [];
  const seenTitles = new Set();
  for (const item of candidates) {
    const key = normalizeTitle(item.title).replace(/\b(the|a|an|of|to|and|in|on|for)\b/g, "").replace(/\s+/g, " ").trim();
    if ([...seenTitles].some((x) => x && key && (x.includes(key) || key.includes(x)))) continue;
    seenTitles.add(key);
    chosen.push(item);
    if (chosen.length >= MAX_ALERTS) break;
  }

  console.log(`Fetched ${items.length} items; ${candidates.length} important unseen; sending ${chosen.length}.`);

  for (const item of chosen) {
    await sendTelegram(buildMessage(item, item.points));
    sent.add(item.id);
    console.log(`Sent [${item.points}] ${item.title}`);
  }

  if (chosen.length) {
    state.sentIds = [...sent];
    await saveState(state);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
