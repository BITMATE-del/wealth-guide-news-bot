import fs from "node:fs/promises";
import crypto from "node:crypto";
import { XMLParser } from "fast-xml-parser";

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const DRY_RUN = process.env.DRY_RUN === "1";
const THRESHOLD = Number(process.env.IMPORTANCE_THRESHOLD || 6);
const MAX_ALERTS = Number(process.env.MAX_ALERTS_PER_RUN || 4);
const STATE_PATH = new URL("../state/news-state.json", import.meta.url);

const GOOGLE_NEWS_QUERIES = [
  { q: "Federal Reserve OR FOMC interest rate inflation CPI PCE jobs", label: "글로벌 경제" },
  { q: "Bank of Korea interest rate inflation won exchange rate Korea economy", label: "한국 경제" },
  { q: "Nasdaq S&P 500 Dow futures market crash rally volatility", label: "미국 증시" },
  { q: "KOSPI KOSDAQ 삼성전자 SK하이닉스 국내 증시 급등 급락 수급 외국인 기관", label: "국내 증시" },
  { q: "코스피 코스닥 상한가 하한가 거래정지 공시 실적 어닝쇼크 어닝서프라이즈", label: "국내주식 속보" },
  { q: "삼성전자 SK하이닉스 현대차 기아 LG에너지솔루션 NAVER 카카오 셀트리온 POSCO 주가", label: "국내 대형주" },
  { q: "반도체 2차전지 바이오 방산 조선 원전 로봇 AI 국내주식 정책 수주 계약", label: "국내 테마주" },
  { q: "금융위원회 금융감독원 한국거래소 공매도 세제 밸류업 자사주 상법 국내 증시", label: "국내 증시 정책" },
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
  [/(earnings|guidance|실적|가이던스|merger|acquisition|m&a|인수|합병|어닝쇼크|어닝서프라이즈|잠정실적)/i, 2],
  [/(공시|수주|공급계약|대규모 계약|유상증자|무상증자|자사주|소각|분할|상장폐지|관리종목|거래정지|상한가|하한가)/i, 4],
  [/(삼성전자|SK하이닉스|현대차|기아|LG에너지솔루션|NAVER|카카오|셀트리온|POSCO|포스코)/i, 2],
  [/(외국인.*(순매수|순매도)|기관.*(순매수|순매도)|프로그램.*매매|공매도|밸류업|금융위원회|금융감독원|한국거래소)/i, 3],
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
  const t = `${item.title} ${item.description} ${item.originalTitle || ""} ${item.originalDescription || ""}`;
  const tags = [];
  if (/(bitcoin|btc|ethereum|eth|crypto|코인|비트코인|이더리움|거래소|stablecoin|스테이블)/i.test(t)) tags.push("코인");
  if (/(nasdaq|s&p|dow|stock|equity|kospi|kosdaq|주식|증시|코스피|코스닥|earnings|실적|공시|수주|상한가|하한가|거래정지)/i.test(t)) tags.push("주식");
  if (/(rate|inflation|cpi|pce|gdp|jobs|yield|dollar|economy|금리|물가|고용|환율|경제|채권)/i.test(t)) tags.push("경제");
  return tags.length ? [...new Set(tags)].join(" · ") : item.label || "시장";
}

function impactHint(item) {
  const t = `${item.title} ${item.description}`;
  if (/(rate hike|금리 인상|inflation.*(higher|rise)|물가.*상승)/i.test(t)) return "금리·채권·달러와 위험자산 변동성 확대 여부를 확인하세요.";
  if (/(rate cut|금리 인하)/i.test(t)) return "채권금리·달러·성장주·가상자산의 동반 반응을 확인하세요.";
  if (/(hack|exploit|해킹|탈취|depeg|디페깅)/i.test(t)) return "관련 거래소·토큰의 입출금 상태와 시장 유동성을 우선 확인하세요.";
  if (/(war|attack|missile|sanction|전쟁|공격|제재)/i.test(t)) return "유가·금·달러·주가지수 선물의 단기 변동성을 확인하세요.";
  if (/(earnings|guidance|실적|가이던스|어닝쇼크|어닝서프라이즈)/i.test(t)) return "해당 종목의 실적 대비 시장 기대치와 동종 업종으로의 영향 확산 여부를 확인하세요.";
  if (/(공시|수주|공급계약|유상증자|무상증자|자사주|소각|분할|거래정지|상장폐지)/i.test(t)) return "공시 원문과 거래소 안내, 해당 종목의 거래 상태 및 수급 변화를 우선 확인하세요.";
  if (/(외국인|기관|공매도|밸류업|금융위원회|금융감독원|한국거래소)/i.test(t)) return "코스피·코스닥 지수와 외국인·기관 수급, 관련 업종의 동반 움직임을 확인하세요.";
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

function hasEnoughKorean(text = "") {
  const s = cleanText(text);
  if (!s) return true;
  const korean = (s.match(/[가-힣]/g) || []).length;
  const letters = (s.match(/[A-Za-z가-힣]/g) || []).length || 1;
  return korean >= 4 || korean / letters >= 0.25;
}

async function translateToKorean(text = "") {
  const src = cleanText(text);
  if (!src || hasEnoughKorean(src)) return src;

  const clipped = src.slice(0, 900);

  // 1차: Google 번역 비공식 엔드포인트
  try {
    const url =
      "https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=ko&dt=t&q=" +
      encodeURIComponent(clipped);

    const res = await fetch(url, {
      headers: { "user-agent": "Mozilla/5.0 WealthGuideNewsBot/1.0" },
      signal: AbortSignal.timeout(10000)
    });

    if (res.ok) {
      const data = await res.json();
      const translated = Array.isArray(data?.[0])
        ? data[0].map((x) => x?.[0] || "").join("")
        : "";
      const cleaned = cleanText(translated);
      if (cleaned && hasEnoughKorean(cleaned)) return cleaned;
    }
  } catch (err) {
    console.warn("Google translation failed:", err?.message || err);
  }

  // 2차: MyMemory 공개 번역 API fallback
  try {
    const url =
      "https://api.mymemory.translated.net/get?q=" +
      encodeURIComponent(clipped) +
      "&langpair=en|ko";

    const res = await fetch(url, {
      headers: { "user-agent": "WealthGuideNewsBot/1.0" },
      signal: AbortSignal.timeout(10000)
    });

    if (res.ok) {
      const data = await res.json();
      const translated = cleanText(data?.responseData?.translatedText || "");
      if (translated && hasEnoughKorean(translated)) return translated;
    }
  } catch (err) {
    console.warn("Fallback translation failed:", err?.message || err);
  }

  return "";
}

async function localizeItem(item) {
  const originalTitle = item.title || "";
  const originalDescription = item.description || "";

  const [translatedTitle, translatedDescription] = await Promise.all([
    translateToKorean(originalTitle),
    translateToKorean(originalDescription)
  ]);

  const title = hasEnoughKorean(originalTitle)
    ? originalTitle
    : translatedTitle;

  const description = hasEnoughKorean(originalDescription)
    ? originalDescription
    : (translatedDescription || "해외 원문 기사입니다. 제목을 한국어로 번역했으며 세부 내용은 원문에서 확인할 수 있습니다.");

  // 영문 제목 번역이 끝내 실패하면 영문 그대로 발송하지 않음
  if (!title || !hasEnoughKorean(title)) {
    return { ...item, originalTitle, originalDescription, skipReason: "translation_failed" };
  }

  return {
    ...item,
    originalTitle,
    originalDescription,
    title,
    description
  };
}

function relatedAssets(item) {
  const t = `${item.title} ${item.description} ${item.originalTitle || ""} ${item.originalDescription || ""}`;
  const related = [];

  const add = (name, why) => {
    if (!related.some((x) => x.name === name)) related.push({ name, why });
  };

  // 국내주식
  if (/(삼성전자|메모리|반도체|HBM|D램|낸드)/i.test(t)) {
    add("삼성전자", "메모리·반도체 업황 및 AI/HBM 수요와 직접 연관");
    add("SK하이닉스", "HBM·메모리 가격과 AI 서버 투자 확대의 직접 수혜/영향");
  }
  if (/(2차전지|배터리|전기차|\bEV\b|리튬|양극재)/i.test(t)) {
    add("LG에너지솔루션", "전기차 수요·배터리 가격·원재료 흐름에 민감");
    add("삼성SDI", "전기차·ESS 배터리 수요와 투자 사이클에 연동");
    add("POSCO퓨처엠", "양극재·배터리 소재 가격 및 수주 이슈와 연관");
  }
  if (/(조선|LNG선|선박|해운 발주)/i.test(t)) {
    add("HD한국조선해양", "선박 발주·선가 상승·LNG선 수주와 연관");
    add("한화오션", "대형 조선 수주와 방산·LNG선 발주 영향");
  }
  if (/(방산|무기|미사일|수출 계약|국방)/i.test(t)) {
    add("한화에어로스페이스", "방산 수출·국방예산 확대와 직접 연관");
    add("LIG넥스원", "유도무기·방산 수출 계약 변화와 연관");
  }
  if (/(원전|SMR|원자력)/i.test(t)) {
    add("두산에너빌리티", "원전·SMR 설비 수주 및 정책 변화와 연관");
  }
  if (/(바이오|신약|임상|FDA|의약품)/i.test(t)) {
    add("삼성바이오로직스", "바이오 위탁생산 수요·글로벌 제약 투자와 연관");
    add("셀트리온", "바이오시밀러·의약품 승인 및 수출 이슈와 연관");
  }
  if (/(NAVER|네이버|AI 서비스|검색 광고|플랫폼)/i.test(t)) {
    add("NAVER", "플랫폼·광고·AI 서비스 성장과 직접 연관");
  }
  if (/(카카오|메신저|플랫폼 규제)/i.test(t)) {
    add("카카오", "플랫폼 규제·광고·콘텐츠 사업 변화와 연관");
  }

  // 미국/글로벌
  if (/(nvidia|엔비디아|ai chip|gpu|hbm)/i.test(t)) {
    add("엔비디아", "AI GPU 수요와 데이터센터 투자 확대의 핵심 종목");
    add("SK하이닉스", "엔비디아향 HBM 공급 기대와 밀접한 연관");
  }
  if (/(tesla|테슬라|ev demand|전기차 수요)/i.test(t)) {
    add("테슬라", "글로벌 전기차 수요·가격정책·마진 변화와 직접 연관");
    add("LG에너지솔루션", "전기차 배터리 수요 변화에 간접 영향");
  }

  // 코인
  if (/(bitcoin|btc|비트코인)/i.test(t)) add("BTC", "비트코인 현물 수급·ETF·거시 유동성 변화와 직접 연관");
  if (/(ethereum|eth|이더리움)/i.test(t)) add("ETH", "이더리움 네트워크·ETF·스테이킹·디파이 수요와 연관");
  if (/(solana|sol|솔라나)/i.test(t)) add("SOL", "솔라나 생태계·네트워크 사용량·밈코인/디앱 활동과 연관");
  if (/(xrp|리플|ripple)/i.test(t)) add("XRP", "리플 관련 규제·소송·결제 사업 이슈와 직접 연관");
  if (/(stablecoin|스테이블코인|usdt|usdc|depeg|디페깅)/i.test(t)) {
    add("USDT", "스테이블코인 유동성·페깅 안정성 변화와 연관");
    add("USDC", "달러 연동 유동성과 거래소·디파이 수요에 연관");
  }
  if (/(exchange hack|거래소 해킹|hack|exploit|해킹|탈취)/i.test(t)) {
    add("BTC", "시장 전반 위험회피 심리와 유동성 위축에 영향 가능");
    add("ETH", "온체인 자금 이동과 디파이 심리 위축에 영향 가능");
  }

  // 거시 변수
  if (/(금리 인하|rate cut|dovish|완화적)/i.test(t)) {
    add("나스닥", "할인율 하락 기대가 성장주 밸류에이션에 우호적일 수 있음");
    add("BTC", "유동성 확대 기대와 위험자산 선호에 연동");
  }
  if (/(금리 인상|rate hike|hawkish|긴축)/i.test(t)) {
    add("나스닥", "할인율 상승 시 성장주 변동성이 커질 수 있음");
    add("BTC", "유동성 축소 우려로 위험자산 변동성이 확대될 수 있음");
  }

  return related.slice(0, 5);
}

function relationBlock(item) {
  const rel = relatedAssets(item);
  if (!rel.length) {
    return [
      "<b>🔗 관련 자산</b>",
      "• 직접 연관 종목·코인이 뚜렷하지 않은 거시/정책 이슈입니다.",
      "• 지수·환율·금리 반응을 우선 확인하세요."
    ].join("\n");
  }
  return [
    "<b>🔗 관련주·관련코인</b>",
    ...rel.map((x) => `• <b>${escapeHtml(x.name)}</b> — ${escapeHtml(x.why)}`)
  ].join("\n");
}

function buildMessage(item, points) {
  const importance = points >= 9 ? "매우 높음" : "높음";
  const area = classify(item);
  const description = truncate(item.description || "세부 내용은 원문에서 확인할 수 있습니다.", 260);
  const category =
    item.label?.includes("국내") ? "🇰🇷 국내시장" :
    item.label?.includes("코인") ? "₿ 디지털자산" :
    item.label?.includes("미국") ? "🇺🇸 미국증시" :
    item.label?.includes("경제") ? "🌐 경제" :
    "🌐 글로벌";

  return [
    "🧭 <b>부의 길잡이 | MARKET BRIEF</b>",
    "<i>부의 방향을 찾다</i>",
    "━━━━━━━━━━━━━━━━━━",
    "",
    `<b>${category} | 중요도 ${importance}</b>`,
    "",
    `📰 <b>${escapeHtml(item.title)}</b>`,
    "",
    "<b>📌 핵심 요약</b>",
    escapeHtml(description),
    "",
    "<b>📊 영향 영역</b>",
    escapeHtml(area),
    "",
    relationBlock(item),
    "",
    "<b>👀 체크포인트</b>",
    escapeHtml(impactHint(item)),
    "",
    `🔎 <a href="${escapeHtml(item.link)}">원문 확인</a>`
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
    const localized = await localizeItem(item);

    if (localized.skipReason === "translation_failed") {
      console.warn(`Skipped English article because Korean translation failed: ${item.title}`);
      continue;
    }

    await sendTelegram(buildMessage(localized, localized.points));
    sent.add(item.id);
    console.log(`Sent [${item.points}] ${localized.title}`);
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
