/* ============================================================
   恋活・婚活自己開示QA Part1 – app.js
   ------------------------------------------------------------
   共有リンクは「id（短いランダムID）＋復号鍵（URLのフラグメント）」
   のみで構成される。回答本体は暗号化されたうえで GAS 経由で
   スプレッドシートに保存され、復号鍵はサーバーに送信されない
   （URLの # 以降はブラウザからサーバーへ送信されないため）。
   ============================================================ */

const LIFF_ID   = "2010312230-hylUrwot";
const DRAFT_KEY = "konkatsu_qa_part1_draft";
const PENDING_SHARED_VIEW_KEY = "konkatsu_qa_part1_pending_shared_view";
// 「クリア」した時刻。これ以前のクラウド下書きは自動復元しない（意図的なクリアを尊重するため）
const DRAFT_CLEARED_AT_KEY = "konkatsu_qa_part1_draft_cleared_at";
// この端末が最後に把握した（保存した／読み込んだ／確認して見送った）クラウド下書きの版（保存時刻）
const DRAFT_SYNCED_AT_KEY = "konkatsu_qa_part1_draft_cloud_synced_at";
// クラウド下書きの暗号鍵導出用（LINEユーザーIDと組み合わせる）。変更すると過去のクラウド下書きは復号できなくなる
const DRAFT_CRYPTO_SALT = "konkatsu_qa_part1_draft_key_v1:";

const GAS_ENDPOINT = "https://script.google.com/macros/s/AKfycbwa7x1G4dHYRNUkfizGSXBcyxUemJzjIfKAtpfkeMJ8YQWYFtG_Om3kwltys85oamai/exec";

/* ------------------------------------------------------------
   選択肢ラベル（表示用 & 統計用の全文テキストとして共用）
   ------------------------------------------------------------ */
const Q14_1_LABELS = {
  "a14-1-1": "返信まで6時間以内（朝LINEしたら昼までには返してほしい）",
  "a14-1-2": "返信まで12時間以内（朝LINEしたら夜までには返してほしい）",
  "a14-1-3": "返信まで24時間以内（朝LINEしたら翌朝までには返してほしい）",
  "a14-1-4": "返信まで3日以内",
  "a14-14":  "3日以上でも日程に余裕があれば待てる",
};
const Q14_2_LABELS = {
  "a14-2-1": "返信まで6時間以内（朝LINEしたら昼までには返してほしい）",
  "a14-2-2": "返信まで12時間以内（朝LINEしたら夜までには返してほしい）",
  "a14-2-3": "返信まで24時間以内（朝LINEしたら翌朝までには返してほしい）",
  "a14-2-4": "返信まで3日以内",
  "a14-2-5": "雑談LINEには返信はあってもなくてもよい",
  "a14-2-6": "雑談LINEは自分は送らないが相手から送られる分には気にしない",
  "a14-2-7": "雑談LINEは送りたくないし送られるのも好きじゃない",
};

/* ------------------------------------------------------------
  ワンポイントアドバイス（各質問の下に表示。回答欄ではなく案内文のみ）
  ------------------------------------------------------------ */
const Q_ADVICE = {
 q1:  "仕事の日と休日で変わりますか？",
 q3:  "流しているだけですか？ちゃんとニュースをチェックしたいタイプですか？",
 q4:  "なんでその番組が好きだったのですか？\n今好きなテレビ番組も聞いてみましょう！",
 q5:  "あだ名の由来やどんな人からそう呼ばれているのかも聞いてみましょう！",
 q7:  "どんな時にネガティブになりやすいですか？",
 q9:  "大きな決断と日常のちょっとしたことを決める時（メニュー選びなど）では変わりますか？\n進学や就活など大きな決断をした時、どうやって決断したのかエピソードも聞いてみましょう！",
 q10: "どうしてその部活・サークルを選んだのですか？\n1番楽しかったこと、大変だったことは何ですか？\nリーダータイプでしたか、サポートタイプでしたか？\n今も続けている趣味があるかも聞いてみましょう！",
 q11: "どうしてそのバイトを選んだのですか？\n1番楽しかったこと、大変だったことは何ですか？",
 q14: "通話とLINEどちらが好みか、聞いてみましょう",
 q15: "どうしてそこに行きたいと思っているんですか？\n具体的に行きたい店舗名などがわかれば聞いてみましょう！\n逆に苦手な場所・シチュエーションがあるかも聞いてみましょう！",
};

/* ------------------------------------------------------------
   Base64URL 変換ユーティリティ（AES鍵・暗号文の符号化に使用）
   ------------------------------------------------------------ */
function bufToBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64UrlToBuf(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad    = padded.length % 4;
  const fixed  = pad ? padded + "=".repeat(4 - pad) : padded;
  const binary = atob(fixed);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/* ------------------------------------------------------------
   SHA-256ハッシュ（LINE UserIDのハッシュ化。生IDはサーバーに送らない）
   ------------------------------------------------------------ */
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/* ------------------------------------------------------------
   AES-GCM 暗号化ユーティリティ
   鍵はURLのフラグメント（#以降）にのみ含め、サーバーには渡さない。
   ------------------------------------------------------------ */
async function generateShareKey() {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const raw = await crypto.subtle.exportKey("raw", key);
  return { key, base64: bufToBase64Url(raw) };
}

async function importShareKey(base64) {
  const raw = base64UrlToBuf(base64);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

async function encryptJSON(obj, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(JSON.stringify(obj));
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc);
  const combined = new Uint8Array(iv.length + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), iv.length);
  return bufToBase64Url(combined.buffer);
}

async function decryptJSON(base64, key) {
  const combined = new Uint8Array(base64UrlToBuf(base64));
  const iv   = combined.slice(0, 12);
  const data = combined.slice(12);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

/* ------------------------------------------------------------
   スライダー値をビジュアル（SVG）に変換
   ------------------------------------------------------------ */
function sliderVisualHTML(value, leftLabel, rightLabel, max = 5) {
  const v = Math.min(Math.max(parseInt(value, 10) || 1, 1), max);

  const width   = 320;
  const padding = 12;
  const usable  = width - padding * 2;
  const step    = usable / (max - 1);
  const cx      = padding + step * (v - 1);
  const y       = 20;

  let ticks = "";
  for (let i = 0; i < max; i++) {
    const x = padding + step * i;
    ticks += `<line x1="${x}" y1="${y - 8}" x2="${x}" y2="${y + 8}" stroke="#f48ca0" stroke-width="2"/>`;
  }

  return `
    <div class="slider-visual">
      <div class="slider-visual-labels">
        <span>${leftLabel}</span>
        <span>${rightLabel}</span>
      </div>
      <svg viewBox="0 0 ${width} 40" xmlns="http://www.w3.org/2000/svg" class="slider-visual-svg">
        <line x1="${padding}" y1="${y}" x2="${width - padding}" y2="${y}" stroke="#f48ca0" stroke-width="2"/>
        ${ticks}
        <circle cx="${cx}" cy="${y}" r="9" fill="#222"/>
      </svg>
    </div>
  `;
}

/* ------------------------------------------------------------
   フォーム値の収集
   ------------------------------------------------------------ */
function collectFormData() {
  const q3Radio    = document.querySelector('input[name="q3"]:checked');
  const q6Radio    = document.querySelector('input[name="q6"]:checked');
  const q14_1Radio = document.querySelector('input[name="q14-1"]:checked');
  const q14_2Radio = document.querySelector('input[name="q14-2"]:checked');

  return {
    q1_wake:  document.getElementById("q1-1").value,
    q1_sleep: document.getElementById("q1-2").value,
    q2:       document.getElementById("q2").value,
    q3:       q3Radio ? q3Radio.value : "",
    q3Detail: document.getElementById("q3Detail").value,
    q4:       document.getElementById("q4").value,
    q5:       document.getElementById("q5").value,
    q6:       q6Radio ? q6Radio.value : "",
    q6Detail: document.getElementById("q6Detail").value,
    q7:       document.getElementById("q7").value,
    q8:       document.getElementById("q8").value,
    q9:       document.getElementById("q9").value,
    q10:      document.getElementById("q10").value,
    q11:      document.getElementById("q11").value,
    q12:      document.getElementById("q12").value,
    q13:      document.getElementById("q13").value,
    q14_1:    q14_1Radio ? q14_1Radio.value : "",
    q14_2:    q14_2Radio ? q14_2Radio.value : "",
    q15:      document.getElementById("q15").value,
  };
}

/* ------------------------------------------------------------
   統計用データの抽出（Analyticsシート行）
   ※ もともと「あだ名」に相当する項目（現在のq5）はAnalyticsシートに
     列が存在せず対象外だったため、踏襲してq5は含めていません。
     実際のGASスクリプト側の列構成と必ず突き合わせて確認してください。
   ------------------------------------------------------------ */
function buildAnalyticsPayload(data) {
  return {
    q1_wake:  data.q1_wake  || "",
    q1_sleep: data.q1_sleep || "",
    q2:       data.q2  || "",
    q3:       data.q3 === "yes" ? "あり" : data.q3 === "no" ? "なし" : "",
    q3Detail: data.q3Detail || "",
    q4:       data.q4  || "",
    q6:       data.q6 === "yes" ? "あり" : data.q6 === "no" ? "なし" : "",
    q6Detail: data.q6Detail || "",
    q7:       data.q7  || "",
    q8:       data.q8  || "",
    q9:       data.q9  || "",
    q10:      data.q10 || "",
    q11:      data.q11 || "",
    q12:      data.q12 || "",
    q13:      data.q13 || "",
    "q14-1":  Q14_1_LABELS[data.q14_1] || "",
    "q14-2":  Q14_2_LABELS[data.q14_2] || "",
    q15:      data.q15 || "",
  };
}

/* ------------------------------------------------------------
   フォームへの値の復元（下書き用）
   ------------------------------------------------------------ */
function restoreFormData(data) {
  if (!data) return;

  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (el && val !== undefined) el.value = val;
  };

  setText("q1-1", data.q1_wake);
  setText("q1-2", data.q1_sleep);
  setText("q2", data.q2);
  setText("q4", data.q4);
  setText("q5", data.q5);
  setText("q7", data.q7);
  setText("q8", data.q8);
  setText("q9", data.q9);
  setText("q10", data.q10);
  setText("q11", data.q11);
  setText("q12", data.q12);
  setText("q13", data.q13);
  setText("q15", data.q15);

  if (data.q3) {
    const r = document.querySelector(`input[name="q3"][value="${data.q3}"]`);
    if (r) { r.checked = true; toggleDetail("q3Detail", data.q3 === "yes"); setText("q3Detail", data.q3Detail); }
  }
  if (data.q6) {
    const r = document.querySelector(`input[name="q6"][value="${data.q6}"]`);
    if (r) { r.checked = true; toggleDetail("q6Detail", data.q6 === "yes"); setText("q6Detail", data.q6Detail); }
  }
  if (data.q14_1) {
    const r = document.querySelector(`input[name="q14-1"][value="${data.q14_1}"]`);
    if (r) r.checked = true;
  }
  if (data.q14_2) {
    const r = document.querySelector(`input[name="q14-2"][value="${data.q14_2}"]`);
    if (r) r.checked = true;
  }
}

/* ------------------------------------------------------------
   詳細テキストエリアの表示/非表示
   ------------------------------------------------------------ */
function toggleDetail(id, show) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.display = show ? "block" : "none";
  if (!show) el.value = "";
}

/* ------------------------------------------------------------
   フォームの初期化（クリアボタン／クラウド下書きで置き換える時に使用）
   ------------------------------------------------------------ */
function resetFormFields() {
  ["q1-1","q1-2","q2","q3Detail","q4","q5","q6Detail","q10","q11","q12","q13","q15"]
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });
  document.querySelectorAll('input[type="radio"]').forEach(r => (r.checked = false));
  document.getElementById("q7").value = 3;
  document.getElementById("q8").value = 3;
  document.getElementById("q9").value = 3;
  toggleDetail("q3Detail", false);
  toggleDetail("q6Detail", false);
}

/* ============================================================
   下書き：二段構え
   ① 自動保存 … 入力のたびに端末（localStorage）へ保存
   ② 「下書き保存」ボタン … 端末 ＋ クラウド（GAS）へ保存
   端末側のデータが消えても、クラウド側から自動復元する。
   クラウド側は「LINEユーザーID由来の鍵」で暗号化してから送るため、
   サーバー側では内容を読めない（共有リンクと同じ考え方）。
   ============================================================ */

/* 入力が空（初期状態）かどうか。空の状態で既存の下書きを上書きしないために使う */
function isBlankForm(d) {
  if (!d) return true;
  const textKeys  = ["q1_wake","q1_sleep","q2","q3Detail","q4","q5","q6Detail","q10","q11","q12","q13","q15"];
  const radioKeys = ["q3","q6","q14_1","q14_2"];
  const sliderKeys = ["q7","q8","q9"];
  if (textKeys.some(k => String(d[k] || "").trim() !== "")) return false;
  if (radioKeys.some(k => d[k])) return false;
  if (sliderKeys.some(k => String(d[k] || 3) !== "3")) return false;
  return true;
}

/* ----- 端末（localStorage） ----- */
function readLocalDraft() {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && parsed.v === 2 && parsed.data) {
      return { data: parsed.data, savedAt: Number(parsed.savedAt) || 0 };
    }
    return { data: parsed, savedAt: 0 }; // 旧形式（フォーム値そのまま）との互換
  } catch (e) {
    console.warn("local draft read failed:", e);
    return null;
  }
}

function writeLocalDraft(data, savedAt = Date.now()) {
  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify({ v: 2, savedAt, data }));
    return true;
  } catch (e) {
    console.warn("local draft write failed:", e);
    return false;
  }
}

function getDraftClearedAt() {
  let ts = 0;
  try { ts = Number(localStorage.getItem(DRAFT_CLEARED_AT_KEY)) || 0; } catch (_) {}
}
function setDraftClearedAt(ts) {
  try { localStorage.setItem(DRAFT_CLEARED_AT_KEY, String(ts)); } catch (_) {}
}

/* この端末が最後に把握したクラウド下書きの「版」。
   端末ごとの時計のずれに左右されないよう、時刻の大小ではなく
   「別の版かどうか（＝別の端末などで更新されたか）」の判定に使う。 */
function getCloudSyncedAt() {
  try { return Number(localStorage.getItem(DRAFT_SYNCED_AT_KEY)) || 0; } catch (_) { return 0; }
}
function setCloudSyncedAt(ts) {
  try { localStorage.setItem(DRAFT_SYNCED_AT_KEY, String(ts)); } catch (_) {}
}

/* ----- クラウド（GAS） ----- */
function fetchWithTimeout(url, options = {}, ms = 15000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...options, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

// 鍵は「ソルト＋LINEユーザーID」のSHA-256。サーバーが持つのはユーザーIDのハッシュ（ownerHash）だけで、
// この鍵は導出できない。
async function getDraftCryptoKey(userId) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(DRAFT_CRYPTO_SALT + userId));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function saveCloudDraft(data, savedAt = Date.now()) {
  const userId     = getLineUserId();
  const ownerHash  = await sha256Hex(userId);
  const key        = await getDraftCryptoKey(userId);
  const cipherText = await encryptJSON(data, key);

  const resp = await fetchWithTimeout(GAS_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" }, // preflight回避
    body: JSON.stringify({ action: "saveDraft", ownerHash, cipherText, savedAt, schemaVersion: 1 }),
  });
  const result = await resp.json();
  if (!result.ok) throw new Error(result.reason || "save_draft_failed");
  setCloudSyncedAt(savedAt); // この端末が保存した版 ＝ 把握済み
  return savedAt;
}

async function loadCloudDraft() {
  const userId    = getLineUserId();
  const ownerHash = await sha256Hex(userId);
  const key       = await getDraftCryptoKey(userId);

  const url  = `${GAS_ENDPOINT}?action=loadDraft&ownerHash=${encodeURIComponent(ownerHash)}`;
  const resp = await fetchWithTimeout(url, { method: "GET" });
  const result = await resp.json();
  if (!result.ok) {
    if (result.reason === "not_found") return null;
    throw new Error(result.reason || "load_draft_failed");
  }
  const data = await decryptJSON(result.cipherText, key);
  return { data, savedAt: Number(result.savedAt) || 0 };
}

/* ----- 起動時：クラウドの下書きを確認して必要なら復元（画面表示はブロックしない） ----- */
async function syncCloudDraft() {
  let cloud;
  try {
    cloud = await loadCloudDraft();
  } catch (e) {
    console.warn("cloud draft load skipped:", e);
    return;
  }
  if (!cloud || isBlankForm(cloud.data)) return;
  if (cloud.savedAt <= getDraftClearedAt()) return; // クリア済み

  const current = collectFormData();

  // 端末側が空（端末のデータが消えた／新しい端末）→ 自動で復元
  if (isBlankForm(current)) {
    resetFormFields();
    restoreFormData(cloud.data);
    writeLocalDraft(cloud.data, cloud.savedAt);
    setCloudSyncedAt(cloud.savedAt);
    return;
  }

  // 端末側にも入力あり。
  // この端末が最後に把握した版と違う（＝別の端末などで更新された）かつ、内容も違う場合だけ確認する
  if (cloud.savedAt === getCloudSyncedAt()) return; // 把握済みの版
  if (JSON.stringify(cloud.data) === JSON.stringify(current)) {
    setCloudSyncedAt(cloud.savedAt); // 内容が同じなら何も聞かず、版だけ揃える
    return;
  }
  const when = cloud.savedAt ? new Date(cloud.savedAt).toLocaleString("ja-JP") : "";
  if (confirm("クラウドに、別の端末などで保存された下書きがあります" + (when ? "（" + when + "）" : "") +
              "。読み込みますか？\n（読み込むと、いま画面にある入力内容は置き換わります）")) {
    resetFormFields();
    restoreFormData(cloud.data);
    writeLocalDraft(cloud.data, cloud.savedAt);
  }
  setCloudSyncedAt(cloud.savedAt); // 読み込んだ場合も、見送った場合も「確認済み」にする
}

/* ----- 送信済みの回答を、自分の下書きとして復元する（共有リンクの所有者のみ） ----- */
async function restoreDraftFromSharedAnswer(sharedData) {
  if (!confirm("この回答を、自分の下書きとして復元します。\n現在保存されている下書きは上書きされます。よろしいですか？")) return;

  const { _shareName, ...formData } = sharedData; // 共有時の表示名は下書きに含めない
  const savedAt = Date.now();
  writeLocalDraft(formData, savedAt);
  try {
    await saveCloudDraft(formData, savedAt);
  } catch (e) {
    console.warn("cloud save during restore failed:", e);
  }
  alert("下書きとして復元しました。回答フォームを開きます。");
  location.href = location.href.split("?")[0].split("#")[0];
}

/* ------------------------------------------------------------
   バリデーション（本送信時のみ）
   ------------------------------------------------------------ */
function validate(data) {
  const errors = [];
  if (!data.q1_wake)                              errors.push("Q1: 起床時間を入力してください。");
  if (!data.q1_sleep)                             errors.push("Q1: 就寝時間を入力してください。");
  if (!data.q2.trim())                            errors.push("Q2: 仕事終わりの過ごし方を入力してください。");
  if (!data.q3)                                   errors.push("Q3: ニュース番組の有無を選択してください。");
  if (data.q3 === "yes" && !data.q3Detail.trim()) errors.push("Q3: 番組名を入力してください。");
  if (!data.q4.trim())                            errors.push("Q4: 子どもの頃好きだったテレビ番組を入力してください。");
  if (!data.q5.trim())                            errors.push("Q5: あだ名を入力してください。");
  if (!data.q6)                                   errors.push("Q6: MBTI診断の有無を選択してください。");
  if (data.q6 === "yes" && !data.q6Detail.trim()) errors.push("Q6: MBTIタイプを入力してください。");
  if (!data.q10.trim())                           errors.push("Q10: 部活動・サークル活動を入力してください。");
  if (!data.q11.trim())                           errors.push("Q11: バイト経験を入力してください。");
  if (!data.q12.trim())                           errors.push("Q12: 休日の友人・家族との過ごし方を入力してください。");
  if (!data.q13.trim())                           errors.push("Q13: 1人での休日の過ごし方を入力してください。");
  if (!data.q14_1)                                errors.push("Q14: デート予定の返信までの許容時間を選択してください。");
  if (!data.q14_2)                                errors.push("Q14: 雑談LINEの頻度を選択してください。");
  if (!data.q15.trim())                           errors.push("Q15: デートで行きたい場所を入力してください。");
  return errors;
}

/* ------------------------------------------------------------
   フォーム要素を隠す（ビューモード／状態表示に切り替える共通処理）
   ------------------------------------------------------------ */
function hideFormElements() {
  document.querySelectorAll(
    ".container > label, .container > input, .container > textarea, " +
    ".container > div.slider-labels, .container > div.button-group, " +
    ".container > div#shareModal"
  ).forEach(el => (el.style.display = "none"));
}

/* ------------------------------------------------------------
   読み込み中／エラーなどの状態表示（共有リンクを開いたとき用）
   ------------------------------------------------------------ */
function showStateCard(title, text, isLoading = false) {
  hideFormElements();
  const container = document.getElementById("viewMode");
  container.style.display = "block";
  container.innerHTML = `
    <div class="view-header state-card">
      ${isLoading ? `
        <div class="state-spinner">
          <img src="https://developers.line.biz/media/line-mini-app/LINE_spinner_light.svg" class="spinner-light" alt="読み込み中">
          <img src="https://developers.line.biz/media/line-mini-app/LINE_spinner_dark.svg" class="spinner-dark" alt="読み込み中">
        </div>
      ` : ""}
      <p class="view-label">${escapeHTML(title)}</p>
      <p class="state-text">${escapeHTML(text)}</p>
    </div>
  `;
}

/* ------------------------------------------------------------
   ビューモード：回答をカード表示
   ------------------------------------------------------------ */
function renderViewMode(data, options = {}) {
  const { selfPreview = false, onShare = null, onRestoreDraft = null } = options;

  const rows = [
    { q: "Q1 朝起きる時間と寝る時間を教えてください。",
       a: `起床 ${data.q1_wake || "未回答"} / 就寝 ${data.q1_sleep || "未回答"}`, tip: Q_ADVICE.q1 },
    { q: "Q2 仕事終わり、どんな過ごし方をしていますか？",                a: data.q2  || "未回答", tip: Q_ADVICE.q2 },
    { q: "Q3 平日の朝いつもつけているニュース/ワイドショー番組はありますか？",
       a: data.q3 === "yes" ? `あり（${data.q3Detail}）` : data.q3 === "no" ? "なし" : "未回答", tip: Q_ADVICE.q3 },
    { q: "Q4 子どもの頃好きだったテレビ番組は何ですか？",              a: data.q4  || "未回答", tip: Q_ADVICE.q4 },
    { q: "Q5 これまでに呼ばれたことのあるあだ名は何ですか？",           a: data.q5  || "未回答", tip: Q_ADVICE.q5 },
    { q: "Q6 MBTI診断したことはありますか？",
       a: data.q6 === "yes" ? `あり（${data.q6Detail}）` : data.q6 === "no" ? "なし" : "未回答" },
    { q: "Q7 ポジティブですか？ネガティブですか？",
       slider: sliderVisualHTML(data.q7 || 3, "ネガティブ", "ポジティブ"), tip: Q_ADVICE.q7 },
    { q: "Q8 周囲の感情などを察する方ですか？",
       slider: sliderVisualHTML(data.q8 || 3, "察さない", "察する"), tip: Q_ADVICE.q8 },
    { q: "Q9 慎重に決めるタイプですか？思い切りがいいタイプですか？",
       slider: sliderVisualHTML(data.q9 || 3, "慎重", "思い切りがいい"), tip: Q_ADVICE.q9 },
    { q: "Q10 部活動、サークル活動は何をしていましたか？",             a: data.q10 || "未回答", tip: Q_ADVICE.q10 },
    { q: "Q11 どんなバイトをしたことがありますか？",                  a: data.q11 || "未回答", tip: Q_ADVICE.q11 },
    { q: "Q12 休みの日に友人や家族と会うことはありますか？",            a: data.q12 || "未回答" },
    { q: "Q13 1人で過ごす時の休みの日の過ごし方を教えてください。",      a: data.q13 || "未回答" },
    { q: "Q14-1 デートなど相談事項の予定調整、返信までどれくらいなら待てますか？（日程に余裕がある場合）",
       a: Q14_1_LABELS[data.q14_1] || "未回答", tip: Q_ADVICE.q14 },
    { q: "Q14-2 雑談LINEはどれくらいの頻度でしたいですか？",
       a: Q14_2_LABELS[data.q14_2] || "未回答" },
    { q: "Q15 今後デートで行きたいところはありますか？",              a: data.q15 || "未回答", tip: Q_ADVICE.q15 },
  ];

  hideFormElements();

  // 自分自身（このLIFFアプリ）の回答フォームURL
  const formURL = location.href.split("?")[0].split("#")[0];

  // 共有画面（ビューモード）の上部注意書きを差し替える
  const descEl = document.querySelector(".form-header .form-description");
  if (descEl) {
    descEl.innerHTML =
      "回答を共有してお互いのことを知りましょう。<br>" +
      "回答内容だけじゃなく、なぜそう思ってるのか、この場合はどう変わるかなども質問し合ってみましょう。";
  }

  const container = document.getElementById("viewMode");
  container.style.display = "block";
  container.innerHTML = `
    ${selfPreview ? `
    <div class="cta-card share-confirm-card">
      <div class="cta-content" style="text-align:center;">
        <h3 class="cta-title">この内容を共有します</h3>
        <p class="cta-text">
          内容を確認したら、共有先を選んでください。
        </p>
        <button type="button" id="goShareBtn" class="cta-button">
          共有先を選ぶ <span class="cta-arrow">›</span>
        </button>
      </div>
    </div>
    ` : `
    <div class="view-header">
      <p class="view-label">回答内容</p>
      ${data._shareName ? `<p class="view-name">${escapeHTML(data._shareName)} さんの回答</p>` : ""}
    </div>
    ${onRestoreDraft ? `
    <div class="cta-card share-confirm-card">
      <div class="cta-content" style="text-align:center;">
        <h3 class="cta-title">あなたが送信した回答です</h3>
        <p class="cta-text">
          この回答を、自分の下書きとして復元できます。
        </p>
        <button type="button" id="restoreDraftBtn" class="cta-button">
          下書きとして復元する <span class="cta-arrow">›</span>
        </button>
      </div>
    </div>
    ` : ""}
    `}

    ${rows.map(({ q, a, slider, tip }) => `
      <div class="view-item">
        <p class="view-question">${escapeHTML(q)}</p>
        ${slider ? slider : `<p class="view-answer">${escapeHTML(a).replace(/\n/g, "<br>")}</p>`}
        ${tip ? `
        <div class="view-tip">
          <span class="view-tip-icon">💡</span>
          <p class="view-tip-text"><strong>あわせて聞いてみましょう：</strong><br>${escapeHTML(tip).replace(/\n/g, "<br>")}</p>
        </div>
        ` : ""}
      </div>
    `).join("")}

    ${!selfPreview ? `
    <div class="cta-card">
      <img src="shareimage.webp" class="cta-image-left" alt="">
      <div class="cta-content">
        <h3 class="cta-title">あなたの価値観も共有してみませんか？</h3>
        <p class="cta-text">
          交際前・交際中の自己開示は、<br>
          お互いを知る大切なきっかけになります。<br>
          あなたの考えや価値観をアンケートで伝えてみましょう。
        </p>
        <button type="button" id="ctaButton" class="cta-button" data-href="${formURL}">
          私も回答する <span class="cta-arrow">›</span>
        </button>
      </div>
    </div>
    ` : ""}
  `;

  if (selfPreview) {
    const goShareBtn = document.getElementById("goShareBtn");
    if (goShareBtn && typeof onShare === "function") {
      goShareBtn.addEventListener("click", onShare);
    }
    return;
  }

  const restoreDraftBtn = document.getElementById("restoreDraftBtn");
  if (restoreDraftBtn && typeof onRestoreDraft === "function") {
    restoreDraftBtn.addEventListener("click", onRestoreDraft);
  }

  const ctaButton = document.getElementById("ctaButton");
  if (ctaButton) {
    ctaButton.addEventListener("click", () => {
      if (confirm("自己開示QA part1を開く")) {
        window.location.href = ctaButton.dataset.href;
      }
    });
  }
}

/* ------------------------------------------------------------
   LINEユーザーIDの取得
   liff.getProfile() はLINEサーバーへの追加API呼び出しが必要で、
   ログイン直後などタイミングによって不安定になりやすい。
   ログイン時に発行されるIDトークンをその場でデコードするだけなら
   通信が発生せず、ユーザーID（sub）を安定して取得できる。
   表示名・プロフィール画像は使わない設計なので、これで十分。
   ------------------------------------------------------------ */
function getLineUserId() {
  const idToken = liff.getDecodedIDToken();
  if (!idToken || !idToken.sub) {
    throw new Error("ID token is not available (sub claim missing)");
  }
  return idToken.sub;
}

/* ------------------------------------------------------------
   スクショ抑止用ウォーターマーク
   ------------------------------------------------------------
   Webアプリの仕様上、スクリーンショットの撮影自体を検知・
   ブロックすることはできない。そのため「撮られても、誰が・いつ
   閲覧した画面かが写り込む」ようにし、無断転載・拡散への
   心理的な抑止力として機能させる。
   閲覧者のLINEユーザーIDハッシュ（先頭8文字）と閲覧日時を、
   画面全体に薄く敷き詰めて表示する。position:fixedのため
   スクロールしても常に画面上に留まる。
   ------------------------------------------------------------ */
function buildWatermarkSVG(lines) {
  const tileW = 240, tileH = 140;
  const lineHeight = 16;
  const startY = tileH / 2 - ((lines.length - 1) * lineHeight) / 2;

  const textEls = lines.map((line, i) => {
    const y = startY + i * lineHeight;
    return `<text x="0" y="${y}" font-size="12" font-family="sans-serif" ` +
           `fill="rgba(0,0,0,0.1)" transform="rotate(-28 ${tileW / 2} ${tileH / 2})">${escapeHTML(line)}</text>`;
  }).join("");

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${tileW}" height="${tileH}">${textEls}</svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

function showScreenshotWatermark(viewerHash) {
  const el = document.getElementById("screenshotWatermark");
  if (!el) return;
  const stamp = new Date().toLocaleString("ja-JP", {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
  const lines = [
    "スクショ・転載禁止",
    `${viewerHash.slice(0, 8)}  ${stamp}`,
  ];
  el.style.backgroundImage = `url("${buildWatermarkSVG(lines)}")`;
  el.classList.add("show");
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ------------------------------------------------------------
   共有：シェアターゲットピッカー用 Flexメッセージ
   共有URLは「id＋鍵」のみで構成される短いリンクになるため、
   ボタン(uriアクション)の1000文字制限に達することはほぼない。
   ------------------------------------------------------------ */
const SHARETARGETPICKER_IMAGE_URL = "https://marriagesketch.github.io/-jikokaiji_qa1-/sharetargetpicker.jpg";

function buildShareFlexMessage(shareName, shareURL) {
  const nameLine = shareName ? `${shareName}さんの回答が届きました` : "回答が届きました";

  return {
    type: "flex",
    altText: `恋活・婚活 自己開示QA Part1 - ${nameLine}`,
    contents: {
      type: "bubble",
      hero: {
        type: "image",
        url: SHARETARGETPICKER_IMAGE_URL,
        size: "full",
        aspectRatio: "3:2",
        aspectMode: "cover"
      },
      body: {
        type: "box",
        layout: "vertical",
        spacing: "md",
        paddingAll: "20px",
        contents: [
          { type: "text", text: "恋活・婚活 自己開示QA Part1", size: "xs", weight: "bold", color: "#d96c7d" },
          { type: "text", text: nameLine, size: "lg", weight: "bold", wrap: true, margin: "sm" },
          { type: "text", text: "ボタンから回答内容を確認できます。", size: "sm", color: "#888888", wrap: true, margin: "md" }
        ]
      },
      footer: {
        type: "box",
        layout: "vertical",
        spacing: "sm",
        paddingAll: "20px",
        contents: [
          {
            type: "button",
            style: "primary",
            height: "sm",
            color: "#f48ca0",
            action: { type: "uri", label: "回答をみる", uri: shareURL }
          }
        ]
      }
    }
  };
}

/* ------------------------------------------------------------
   共有先を選んで送信する
   ------------------------------------------------------------ */
async function shareToOthers(flexMessage, fallbackLineSchemeURL) {
  if (liff.isApiAvailable("shareTargetPicker")) {
    try {
      await liff.shareTargetPicker([flexMessage], { isMultiple: true });
      return;
    } catch (e) {
      console.warn("shareTargetPicker failed, falling back to URL scheme:", e);
    }
  }

  if (liff.isInClient()) {
    window.location.href = fallbackLineSchemeURL;
  } else {
    window.open(fallbackLineSchemeURL, "_blank");
  }
}


/* ------------------------------------------------------------
   友だち追加チェック
   ------------------------------------------------------------ */
async function checkFriendship() {
  try {
    const friendship = await liff.getFriendship();
    if (!friendship.friendFlag) {
      try {
        await liff.requestFriendship();
      } catch (error) {
        console.warn("友だち追加リクエスト失敗（ユーザーがキャンセルした可能性があります）:", error);
      }
    }
  } catch (error) {
    console.warn("友だち確認をスキップ:", error);
  }
}

/* ------------------------------------------------------------
   共有リンクを開いたときの処理
   ・URLの ?id=... がスプレッドシート上のレコードを指す
   ・URLの #以降 が復号鍵（サーバーには送信されない）
   ・閲覧にはLINEログインが必須（viewerHashによるアクセス制御のため）
   ------------------------------------------------------------ */
async function handleSharedView(id) {
  // ここに来た時点で liff.init() は完了済み（呼び出し元のメイン処理を参照）。
  showStateCard("読み込み中…", "回答内容を確認しています。少々お待ちください。", true);

  const keyBase64 = location.hash ? location.hash.slice(1) : "";
  if (!keyBase64) {
    showStateCard(
      "リンクが不完全です",
      "共有リンクが途中で切れているか、正しくコピーされていない可能性があります。共有した相手にもう一度リンクを送ってもらってください。"
    );
    return;
  }

  if (!liff.isLoggedIn()) {
    // LINEログイン画面へ遷移する前に、共有リンク情報（id・復号鍵）を
    // sessionStorageへ退避しておく。ログイン往復後にURLの
    // ?id=...#鍵 が正しく復元されないブラウザ・状況があり、その場合に
    // 自分の回答フォーム側へ誤って遷移してしまう不具合の対策。
    try {
      sessionStorage.setItem(PENDING_SHARED_VIEW_KEY, location.href);
    } catch (_) {}
    liff.login();
    return;
  }

  let key;
  try {
    key = await importShareKey(keyBase64);
  } catch (e) {
    console.error("key import error", e);
    showStateCard("リンクが正しくありません", "共有リンクが壊れている可能性があります。");
    return;
  }

  let viewerHash;
  try {
    const userId = getLineUserId();
    viewerHash = await sha256Hex(userId);
  } catch (e) {
    console.error("get user id error", e);
    showStateCard(
      "エラー",
      "LINEアカウント情報の確認に失敗しました。時間をおいてもう一度お試しください。" +
      "（詳細: " + (e && e.message ? e.message : String(e)) + "）"
    );
    return;
  }

  let result;
  try {
    const url = `${GAS_ENDPOINT}?action=view&id=${encodeURIComponent(id)}&viewerHash=${encodeURIComponent(viewerHash)}`;
    const resp = await fetch(url, { method: "GET" });
    result = await resp.json();
  } catch (e) {
    console.error("fetch view error", e);
    showStateCard("通信エラー", "回答内容を取得できませんでした。通信環境を確認してもう一度お試しください。");
    return;
  }

  if (!result.ok) {
    if (result.reason === "forbidden") {
      showStateCard(
        "閲覧できません",
        "このリンクは最初に開いた方専用です。転送されたリンクは、その方以外は閲覧できない仕組みになっています。"
      );
    } else if (result.reason === "revoked" || result.reason === "expired" || result.reason === "deleted") {
      showStateCard("リンクが無効です", "このリンクはすでに無効になっています。最新の共有リンクを送ってもらってください。");
    } else if (result.reason === "not_found") {
      showStateCard("リンクが見つかりません", "このリンクは存在しないか、削除された可能性があります。");
    } else {
      showStateCard("エラー", "回答内容を取得できませんでした。時間をおいて再度お試しください。");
    }
    return;
  }

  let data;
  try {
    data = await decryptJSON(result.cipherText, key);
  } catch (e) {
    console.error("decrypt error", e);
    showStateCard("復号に失敗しました", "リンクの一部が正しくない可能性があります。共有した相手にもう一度リンクを送ってもらってください。");
    return;
  }

  // GAS側が isOwner: true を返した場合（閲覧者＝共有を作成した本人）のみ、下書き復元ボタンを出す
  renderViewMode(data, result.isOwner === true
    ? { onRestoreDraft: () => restoreDraftFromSharedAnswer(data) }
    : {});
  showScreenshotWatermark(viewerHash);
}

/* ------------------------------------------------------------
   メイン処理
   ------------------------------------------------------------ */
(async () => {

  /* ----- LIFF 初期化（必ず最初に1回だけ実行） -----
     共有リンク判定に使うURL（?id=...#key）の読み取りは、
     必ずこの後で行う。ログインのリダイレクトを経由して
     戻ってきた直後は、URLが一時的に ?liff.state=... の形に
     なっていて ?id=... が正しく読み取れないことがあるため。
  ----- */
  try {
    await liff.init({ liffId: LIFF_ID });
  } catch (e) {
    console.error("LIFF init failed", e);
    alert("LIFFの初期化に失敗しました。");
    return;
  }

  try {

  /* ----- 共有リンク判定（?id=... が付いている場合） -----
     LINEログインへのリダイレクトを経由した直後は、ブラウザや状況に
     よってURLの ?id=...#鍵 が正しく復元されないことがある。その場合は
     handleSharedView側でliff.login()前にsessionStorageへ退避しておいた
     URLから復元する（フォールバック）。 */
  let sharedId = new URLSearchParams(location.search).get("id");
  if (!sharedId) {
    try {
      const pending = sessionStorage.getItem(PENDING_SHARED_VIEW_KEY);
      if (pending) {
        const pendingURL = new URL(pending);
        const pendingId = new URLSearchParams(pendingURL.search).get("id");
        if (pendingId) {
          sharedId = pendingId;
          const restoredHash = location.hash || pendingURL.hash;
          history.replaceState(null, "", location.pathname + pendingURL.search + restoredHash);
        }
      }
    } catch (_) {}
  }
  try { sessionStorage.removeItem(PENDING_SHARED_VIEW_KEY); } catch (_) {}

  if (sharedId) {
    await handleSharedView(sharedId);
    return;
  }

  if (!liff.isLoggedIn()) {
    liff.login();
    return;
  }

  /* ----- 友だち追加チェック -----
     liff.getFriendship() / requestFriendship() はLINEサーバーへの通信を
     伴うため、ここをawaitすると電波が悪い時に画面表示自体が止まって
     しまう。必須の処理ではないので、裏側で実行させて画面構築は
     先に進める（fire-and-forget）。 */
  checkFriendship();

  /* ----- 下書き復元：①端末（localStorage）→ ②クラウド（裏で確認） ----- */
  const localDraft = readLocalDraft();
  if (localDraft) {
    try {
      restoreFormData(localDraft.data);
    } catch (e) {
      console.warn("local draft restore failed:", e);
    }
  }

  /* ----- Q3 / Q6 ラジオ：詳細テキストエリアの表示制御 ----- */
  document.querySelectorAll('input[name="q3"]').forEach(r =>
    r.addEventListener("change", () => toggleDetail("q3Detail", r.value === "yes"))
  );
  document.querySelectorAll('input[name="q6"]').forEach(r =>
    r.addEventListener("change", () => toggleDetail("q6Detail", r.value === "yes"))
  );

  const q3c = document.querySelector('input[name="q3"]:checked');
  toggleDetail("q3Detail", q3c ? q3c.value === "yes" : false);
  const q6c = document.querySelector('input[name="q6"]:checked');
  toggleDetail("q6Detail", q6c ? q6c.value === "yes" : false);

  /* ----- 自動保存（端末）-----
     入力のたびに（0.5秒まとめて）端末へ保存。画面を離れる／アプリが
     バックグラウンドに回る時にも即時保存する。
     入力が空の状態では保存しない（既存の下書きを空で上書きしないため）。 */
  let autosaveTimer = null;
  const flushAutosave = () => {
    clearTimeout(autosaveTimer);
    autosaveTimer = null;
    const data = collectFormData();
    if (isBlankForm(data)) return;
    const saved = readLocalDraft();
    if (saved && JSON.stringify(saved.data) === JSON.stringify(data)) return; // 変更なし → 保存時刻は更新しない
    writeLocalDraft(data);
  };
  const scheduleAutosave = (e) => {
    if (e && e.target && e.target.closest && e.target.closest("#shareModal")) return;
    clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(flushAutosave, 500);
  };
  document.addEventListener("input", scheduleAutosave);
  document.addEventListener("change", scheduleAutosave);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") flushAutosave();
  });
  window.addEventListener("pagehide", flushAutosave);

  /* ----- クラウドの下書きを確認（裏で実行。画面表示は止めない） ----- */
  syncCloudDraft();

  /* ----- 下書き保存（端末 ＋ クラウド） ----- */
  document.getElementById("draftBtn").addEventListener("click", async () => {
    const draftBtn = document.getElementById("draftBtn");
    const data = collectFormData();
    if (isBlankForm(data)) {
      alert("入力内容がまだありません。");
      return;
    }

    const savedAt = Date.now();
    const localOk = writeLocalDraft(data, savedAt);

    const originalLabel = draftBtn.textContent;
    draftBtn.disabled = true;
    draftBtn.textContent = "保存中…";
    try {
      await saveCloudDraft(data, savedAt);
      alert(localOk
        ? "下書きを保存しました。\n（この端末とクラウドの両方に保存されています）"
        : "クラウドに下書きを保存しました。\n（この端末への保存は失敗しました）");
    } catch (e) {
      console.warn("cloud draft save failed:", e);
      alert(localOk
        ? "この端末には保存しましたが、クラウドへの保存に失敗しました。\n通信環境を確認して、もう一度お試しください。"
        : "下書きの保存に失敗しました。通信環境を確認して、もう一度お試しください。");
    } finally {
      draftBtn.disabled = false;
      draftBtn.textContent = originalLabel;
    }
  });

  /* ----- フォームクリア ----- */
  document.getElementById("clearBtn").addEventListener("click", () => {
    if (!confirm("入力内容をすべてクリアしますか？")) return;
    clearTimeout(autosaveTimer);
    resetFormFields();
    try { localStorage.removeItem(DRAFT_KEY); } catch (_) {}
    // 意図的なクリア。これ以前に保存したクラウド下書きは、次回起動時に自動復元しない
    setDraftClearedAt(Date.now());
  });

  /* ----- 送信ボタン ----- */
  document.getElementById("submitBtn").addEventListener("click", () => {
    const data   = collectFormData();
    const errors = validate(data);
    if (errors.length > 0) {
      alert("以下の項目を入力してください。\n\n" + errors.join("\n"));
      return;
    }
    // 前回の回答として保存（次回編集時に復元できるようにする）
    writeLocalDraft(data);

    document.getElementById("submitBtn").disabled = true;

    const modal = document.getElementById("shareModal");
    modal.classList.remove("hidden");
    modal.classList.add("show");
  });

  /* ----- 共有ボタン ----- */
  document.getElementById("shareBtn").addEventListener("click", async () => {
    const shareBtn = document.getElementById("shareBtn");
    const shareName = document.getElementById("shareName").value.trim();
    const formData  = collectFormData();
    const data      = { ...formData, _shareName: shareName };

    shareBtn.disabled = true;
    const originalLabel = shareBtn.textContent;
    shareBtn.textContent = "送信中…";

    try {
      const userId    = getLineUserId();
      const ownerHash = await sha256Hex(userId);

      const id = (crypto.randomUUID ? crypto.randomUUID() : fallbackUUID());
      const { key, base64: keyBase64 } = await generateShareKey();
      const cipherText = await encryptJSON(data, key);
      const analytics  = buildAnalyticsPayload(data);

      const resp = await fetch(GAS_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "text/plain;charset=utf-8" }, // preflight回避のため text/plain を使用
        body: JSON.stringify({ action: "share", id, cipherText, ownerHash, analytics, schemaVersion: 1 }),
      });
      const result = await resp.json();
      if (!result.ok) throw new Error(result.reason || "share_failed");

      // 共有に成功した回答を、クラウドの下書きにも保存しておく（失敗しても共有処理は止めない）。
      // 端末のデータが消えても、送信済みの回答を下書きとして復元できるようにするため。
      saveCloudDraft(formData).catch(e => console.warn("cloud draft save after share failed:", e));

      const base     = location.href.split("?")[0].split("#")[0];
      const shareURL = `${base}?id=${id}#${keyBase64}`;

      const previewMsg = shareName
        ? `${shareName}さんの恋活・婚活　自己開示QA part1の回答が届きました。\n回答をみる→${shareURL}`
        : `恋活・婚活　自己開示QA part1の回答が届きました。\n回答をみる→${shareURL}`;

      const flexMessage = buildShareFlexMessage(shareName, shareURL);

      // モーダルを閉じる
      const modal = document.getElementById("shareModal");
      modal.classList.remove("show");
      modal.classList.add("hidden");

      // まず本人の画面を「回答内容」プレビューに切り替える
      renderViewMode(data, {
        selfPreview: true,
        onShare: () => {
          const lineShareURL = `https://line.me/R/msg/text/?${encodeURIComponent(previewMsg)}`;
          shareToOthers(flexMessage, lineShareURL);
        },
      });

      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (e) {
      console.error("share error", e);
      alert("共有の準備に失敗しました。通信環境を確認してもう一度お試しください。");
      document.getElementById("submitBtn").disabled = false;
    } finally {
      shareBtn.disabled = false;
      shareBtn.textContent = originalLabel;
    }
  });

  /* ----- モーダル外クリックで閉じる ----- */
  document.getElementById("shareModal").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) {
      e.currentTarget.classList.remove("show");
      e.currentTarget.classList.add("hidden");
    }
  });

  } catch (e) {
    // フォーム構築中に想定外のエラーが起きた場合、無音で失敗させず
    // コンソール＋画面上に手がかりを残す（IDのタイポ等の検知用）。
    console.error("initialization failed", e);
    alert("画面の初期化に失敗しました。（詳細: " + (e && e.message ? e.message : String(e)) + "）");
  }

})();

/* crypto.randomUUID が使えない古い環境用のフォールバック */
function fallbackUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
