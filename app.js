/* ============================================================
   婚活自己開示QA Part1 – app.js
   ------------------------------------------------------------
   共有リンクは「id（短いランダムID）＋復号鍵（URLのフラグメント）」
   のみで構成される。回答本体は暗号化されたうえで GAS 経由で
   スプレッドシートに保存され、復号鍵はサーバーに送信されない
   （URLの # 以降はブラウザからサーバーへ送信されないため）。
   ============================================================ */

const LIFF_ID   = "2010312230-hylUrwot";
const DRAFT_KEY = "konkatsu_qa_part1_draft";
const PENDING_SHARED_VIEW_KEY = "konkatsu_qa_part1_pending_shared_view";

const GAS_ENDPOINT = "https://script.google.com/macros/s/AKfycbwa7x1G4dHYRNUkfizGSXBcyxUemJzjIfKAtpfkeMJ8YQWYFtG_Om3kwltys85oamai/exec";

/* ------------------------------------------------------------
   選択肢ラベル（表示用 & 統計用の全文テキストとして共用）
   ------------------------------------------------------------ */
const Q14_1_LABELS = {
  "a14-1-1": "返信まで6時間以内（朝LINEしたら昼までには返してほしい）",
  "a14-1-2": "返信まで12時間以内（朝LINEしたら夜までには返してほしい）",
  "a14-1-3": "返信まで24時間以内（朝LINEしたら翌朝までには返してほしい）",
  "a14-1-4": "返信まで3日以内",
  // 注意: index.html側のvalueが "a14-1-5" ではなく "a14-14" になっているため、
  // それに合わせています。可能であればHTML側を "a14-1-5" に修正してください。
  "a14-14": "3日以上でも日程に余裕があれば待てる",
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
 q1:  "休みの日は時間が変わりますか？\n朝型・夜型でいうとどちらですか？",
 q2:  "仕事終わりの過ごし方で、特にこれをしていると楽しい・幸せということは何ですか？",
 q3:  "流しているだけですか？ちゃんとニュースをチェックしたいタイプですか？\nこのチャンネルをつけているのは幼少期ご家族の影響ですか？",
 q4:  "なんでその番組が好きだったのですか？\n今好きなテレビ番組も聞いてみましょう！",
 q5:  "あだ名の由来は何ですか？\nどんな人からそう呼ばれていますか？",
 q7:  "どんな時にネガティブになりやすいですか？",
 q8:  "察してほしいタイプですか？はっきり伝えてほしいタイプですか？",
 q9:  "大きな決断と日常のちょっとしたことを決める時（メニュー選びなど）では変わりますか？\n進学や就活など大きな決断をした時、どうやって決断したのかエピソードも聞いてみましょう！",
 q10: "どうしてその部活・サークルを選んだのですか？\n1番楽しかったこと、大変だったことは何ですか？\nリーダータイプでしたか、サポートタイプでしたか？\nこのなかで今も趣味として続けているものはありますか？",
 q11: "どうしてそのバイトを選んだのですか？\n1番楽しかったこと、大変だったことは何ですか？",
 q12: "休日の過ごし方で、特にこれをしていると楽しい・幸せということは何ですか？",
 q14: "電話は好きですか？通話とLINEどちらが好みですか？",
 q15: "どうしてそこに行きたいと思っているのですか？\n具体的に行きたい店舗名などがわかれば聞いてみましょう！\n逆に苦手な場所・シチュエーションはありますか？",
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
   下書き移行（受信側）
   ------------------------------------------------------------
   旧LINEミニアプリ側で送信された下書きを、userIdから独自に導出した
   鍵で復号して復元する。鍵はサーバーに一切渡さない（送信側と同じ
   導出ロジックで、このアプリ側でも独立に計算する）。
   ・新LIFF側に既に下書きがある場合は、勝手に上書きしない。
   ・復元前に必ずユーザーへ確認ダイアログを出す。
   ・GAS側のdraft_migrate_fetchは取得後に該当データを削除するため、
     一度復元されたらサーバー側の控えは残らない。
   ------------------------------------------------------------ */
async function deriveMigrationKey(userId) {
  const raw = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(userId + ":draft_migration_v1")
  );
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

async function decryptMigratedDraft(base64, key) {
  const combined = new Uint8Array(base64UrlToBuf(base64));
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

async function tryRestoreMigratedDraft() {
  try {
    // 新LIFF側に既に下書きがあるなら何もしない（上書き事故防止）
    if (localStorage.getItem(DRAFT_KEY)) return;

    const userId = getLineUserId();
    const ownerHash = await sha256Hex(userId);

    const resp = await fetch(GAS_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify({ action: "draft_migrate_fetch", ownerHash }),
    });
    const result = await resp.json();
    if (!result.ok || !result.found || !result.cipherText) return;

    const key = await deriveMigrationKey(userId);
    const draftObj = await decryptMigratedDraft(result.cipherText, key);

    const ok = confirm("以前保存されていた下書きが見つかりました。復元しますか？");
    if (!ok) return;

    localStorage.setItem(DRAFT_KEY, JSON.stringify(draftObj));
  } catch (e) {
    console.error("draft migration restore failed", e);
    // 失敗時は何もしない（通常の新規入力フローにフォールバック）
  }
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
  // ※ ここでの内部フィールド名（q1〜q16等）はAnalyticsシートの列構成に
  //   合わせて維持しています。実際の画面上のQ番号とは1つずれています
  //   （新HTMLではQ1が起床/就寝時間の統合になったため）。
  const q3Radio    = document.querySelector('input[name="q3"]:checked');
  const q6Radio    = document.querySelector('input[name="q6"]:checked');
  const q14_1Radio = document.querySelector('input[name="q14-1"]:checked');
  const q14_2Radio = document.querySelector('input[name="q14-2"]:checked');

  return {
    q1:       document.getElementById("q1-1").value,   // 起床時間（画面Q1）
    q2:       document.getElementById("q1-2").value,   // 就寝時間（画面Q1）
    q3:       document.getElementById("q2").value,     // 仕事終わりの過ごし方（画面Q2）
    q4:       q3Radio  ? q3Radio.value  : "",           // ニュース番組の有無（画面Q3）
    q4Detail: document.getElementById("q3Detail").value,
    q5:       document.getElementById("q4").value,     // 子どもの頃好きだった番組（画面Q4）
    q6:       document.getElementById("q5").value,     // あだ名（画面Q5）
    q7:       q6Radio  ? q6Radio.value  : "",           // MBTI診断の有無（画面Q6）
    q7Detail: document.getElementById("q6Detail").value,
    q8:       document.getElementById("q7").value,     // ポジティブ/ネガティブ（画面Q7）
    q9:       document.getElementById("q8").value,     // 察する方か（画面Q8）
    q10:      document.getElementById("q9").value,     // 慎重/思い切り（画面Q9）
    q11:      document.getElementById("q10").value,    // 部活動・サークル（画面Q10）
    q12:      document.getElementById("q11").value,    // バイト（画面Q11）
    q13:      document.getElementById("q12").value,    // 休みの日（友人家族）（画面Q12）
    q14:      document.getElementById("q13").value,    // 1人での休日（画面Q13）
    q15_1:    q14_1Radio ? q14_1Radio.value : "",       // LINE頻度（デート予定）（画面Q14）
    q15_2:    q14_2Radio ? q14_2Radio.value : "",       // LINE頻度（雑談）（画面Q14）
    q16:      document.getElementById("q15").value,    // デートで行きたいところ（画面Q15）
  };
}

/* ------------------------------------------------------------
   統計用データの抽出（Analyticsシート行）
   ※ ここで返すオブジェクトのキー名は、Analyticsシートのヘッダー行
     （q1-1, q1-2, q2, q3, q3Detail, q4, q6, q6Detail, q7, q8, q9,
      q10, q11, q12, q13, q14-1, q14-2, q15）と1対1で対応させている。
     ヘッダー行の列名や並び順を変えた場合は、必ずこちらも合わせて
     修正すること（code.gs側のACOL/appendRowとも一致させる必要あり）。
   あだ名（画面Q5）は列自体が存在しないため対象外。
   選択式の項目は、集計時にそのまま使えるよう選択肢の全文を入れる。
   ※ ここで送られる内容はAnalyticsシートに平文で記録されるため、
     管理者から自由記述の内容も見える状態になる点に留意すること。
   ------------------------------------------------------------ */
function buildAnalyticsPayload(data) {
  return {
    "q1-1":   data.q1  || "",                                              // 起床時間
    "q1-2":   data.q2  || "",                                              // 就寝時間
    q2:       data.q3  || "",                                              // 仕事終わりの過ごし方
    q3:       data.q4 === "yes" ? "あり" : data.q4 === "no" ? "なし" : "", // ニュース番組の有無
    q3Detail: data.q4Detail || "",                                         // ニュース番組名
    q4:       data.q5  || "",                                              // 子どもの頃好きだった番組
    q6:       data.q7 === "yes" ? "あり" : data.q7 === "no" ? "なし" : "", // MBTI診断の有無
    q6Detail: data.q7Detail || "",                                         // MBTIタイプ
    q7:       data.q8  || "",                                              // ポジティブ/ネガティブ
    q8:       data.q9  || "",                                              // 察する方か
    q9:       data.q10 || "",                                              // 慎重/思い切り
    q10:      data.q11 || "",                                              // 部活動・サークル
    q11:      data.q12 || "",                                              // バイト
    q12:      data.q13 || "",                                              // 休みの日（友人・家族）
    q13:      data.q14 || "",                                              // 1人での休日
    "q14-1":  Q14_1_LABELS[data.q15_1] || "",                              // LINE頻度（デート予定）
    "q14-2":  Q14_2_LABELS[data.q15_2] || "",                              // LINE頻度（雑談）
    q15:      data.q16 || "",                                              // デートで行きたいところ
  };
}

/* ------------------------------------------------------------
   フォームへの値の復元（下書き用。localStorageのみで完結）
   ------------------------------------------------------------ */
function restoreFormData(data) {
  if (!data) return;

  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (el && val !== undefined) el.value = val;
  };

  setText("q1-1", data.q1);
  setText("q1-2", data.q2);
  setText("q2", data.q3);
  setText("q4", data.q5);
  setText("q5", data.q6);
  setText("q7", data.q8);
  setText("q8", data.q9);
  setText("q9", data.q10);
  setText("q10", data.q11);
  setText("q11", data.q12);
  setText("q12", data.q13);
  setText("q13", data.q14);
  setText("q15", data.q16);

  if (data.q4) {
    const r = document.querySelector(`input[name="q3"][value="${data.q4}"]`);
    if (r) { r.checked = true; toggleDetail("q3Detail", data.q4 === "yes"); setText("q3Detail", data.q4Detail); }
  }
  if (data.q7) {
    const r = document.querySelector(`input[name="q6"][value="${data.q7}"]`);
    if (r) { r.checked = true; toggleDetail("q6Detail", data.q7 === "yes"); setText("q6Detail", data.q7Detail); }
  }
  if (data.q15_1) {
    const r = document.querySelector(`input[name="q14-1"][value="${data.q15_1}"]`);
    if (r) r.checked = true;
  }
  if (data.q15_2) {
    const r = document.querySelector(`input[name="q14-2"][value="${data.q15_2}"]`);
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
   バリデーション（本送信時のみ）
   ------------------------------------------------------------ */
function validate(data) {
  const errors = [];
  if (!data.q1)                                   errors.push("Q1: 起床時間を入力してください。");
  if (!data.q2)                                   errors.push("Q1: 就寝時間を入力してください。");
  if (!data.q3.trim())                            errors.push("Q2: 仕事終わりの過ごし方を入力してください。");
  if (!data.q4)                                   errors.push("Q3: ニュース番組の有無を選択してください。");
  if (data.q4 === "yes" && !data.q4Detail.trim()) errors.push("Q3: 番組名を入力してください。");
  if (!data.q5.trim())                            errors.push("Q4: 子どもの頃好きだったテレビ番組を入力してください。");
  if (!data.q6.trim())                            errors.push("Q5: あだ名を入力してください。");
  if (!data.q7)                                   errors.push("Q6: MBTI診断の有無を選択してください。");
  if (data.q7 === "yes" && !data.q7Detail.trim()) errors.push("Q6: MBTIタイプを入力してください。");
  if (!data.q11.trim())                           errors.push("Q10: 部活動・サークル活動を入力してください。");
  if (!data.q12.trim())                           errors.push("Q11: バイト経験を入力してください。");
  if (!data.q13.trim())                           errors.push("Q12: 休日の友人・家族との過ごし方を入力してください。");
  if (!data.q14.trim())                           errors.push("Q13: 1人での休日の過ごし方を入力してください。");
  if (!data.q15_1)                                errors.push("Q14: デート予定の返信までの許容時間を選択してください。");
  if (!data.q15_2)                                errors.push("Q14: 雑談LINEの頻度を選択してください。");
  if (!data.q16.trim())                           errors.push("Q15: デートで行きたい場所を入力してください。");
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
  const { selfPreview = false, onShare = null } = options;

  const rows = [
    { q: "Q1 朝起きる時間と寝る時間を教えてください。",
       a: `起床：${data.q1 || "未回答"} / 就寝：${data.q2 || "未回答"}`,
       tip: Q_ADVICE.q1 },
    { q: "Q2 仕事終わり、どんな過ごし方をしていますか？",              a: data.q3  || "未回答", tip: Q_ADVICE.q2 },
    { q: "Q3 平日の朝いつもつけているニュース/ワイドショー番組はありますか？",
       a: data.q4 === "yes" ? `あり（${data.q4Detail}）` : data.q4 === "no" ? "なし" : "未回答", tip: Q_ADVICE.q3 },
    { q: "Q4 子どもの頃好きだったテレビ番組は何ですか？",              a: data.q5  || "未回答", tip: Q_ADVICE.q4 },
    { q: "Q5 これまでに呼ばれたことのあるあだ名は何ですか？",           a: data.q6  || "未回答", tip: Q_ADVICE.q5 },
    { q: "Q6 MBTI診断したことはありますか？",
       a: data.q7 === "yes" ? `あり（${data.q7Detail}）` : data.q7 === "no" ? "なし" : "未回答", tip: Q_ADVICE.q6 },
    { q: "Q7 ポジティブですか？ネガティブですか？",
       slider: sliderVisualHTML(data.q8 || 3, "ネガティブ", "ポジティブ"), tip: Q_ADVICE.q7 },
    { q: "Q8 周囲の感情などを察する方ですか？",
       slider: sliderVisualHTML(data.q9 || 3, "察さない", "察する"), tip: Q_ADVICE.q8 },
    { q: "Q9 慎重に決めるタイプですか？思い切りがいいタイプですか？",
       slider: sliderVisualHTML(data.q10 || 3, "慎重", "思い切りがいい"), tip: Q_ADVICE.q9 },
    { q: "Q10 部活動、サークル活動は何をしていましたか？",             a: data.q11 || "未回答", tip: Q_ADVICE.q10 },
    { q: "Q11 どんなバイトをしたことがありますか？",                  a: data.q12 || "未回答", tip: Q_ADVICE.q11 },
    { q: "Q12 休みの日に友人や家族と会うことはありますか？",            a: data.q13 || "未回答", tip: Q_ADVICE.q12 },
    { q: "Q13 1人で過ごす時の休みの日の過ごし方を教えてください。",      a: data.q14 || "未回答", tip: Q_ADVICE.q13 },
    { q: "Q14-1 デートなど相談事項の予定調整、返信までどれくらいなら待てますか？（日程に余裕がある場合）",
       a: Q14_1_LABELS[data.q15_1] || "未回答", tip: Q_ADVICE.q14 },
    { q: "Q14-2 雑談LINEはどれくらいの頻度でしたいですか？",
       a: Q14_2_LABELS[data.q15_2] || "未回答" },
    { q: "Q15 今後デートで行きたいところはありますか？",              a: data.q16 || "未回答", tip: Q_ADVICE.q15 },
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
      <img src="image1.PNG" class="cta-image-left" alt="">
      <div class="cta-content">
        <h3 class="cta-title">あなたの価値観も共有してみませんか？</h3>
        <p class="cta-text">
          婚活・交際前の自己開示は、<br>
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
const HEADER_IMAGE_URL = "https://marriagesketch.github.io/-jikokaiji_qa1-/image_message.jpg";

function buildShareFlexMessage(shareName, shareURL) {
  const nameLine = shareName ? `${shareName}さんの回答が届きました` : "回答が届きました";

  return {
    type: "flex",
    altText: `婚活 自己開示QA Part1 - ${nameLine}`,
    contents: {
      type: "bubble",
      hero: {
        type: "image",
        url: HEADER_IMAGE_URL,
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
          { type: "text", text: "婚活 自己開示QA Part1", size: "xs", weight: "bold", color: "#d96c7d" },
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

  renderViewMode(data);
}

/* ============================================================
   複数アプリ一括下書き移行チェーン 受け取り処理
   （婚活すり合わせシリーズ 5サイト共通スニペット。中身は全サイト同一）
   ============================================================ */
(function () {
  const params = new URLSearchParams(location.search);
  if (params.get("migrate") !== "1" || !location.hash) return;

  window.__migrationInProgress = true;

  try {
    const idx = parseInt(params.get("idx") || "0", 10);
    const encoded = location.hash.slice(1);
    const binary = atob(encoded.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    const chain = JSON.parse(new TextDecoder().decode(bytes));

    const item = chain[idx];
    if (item && item.value != null) {
      localStorage.setItem(item.draftKey, item.value);
    }

    const next = chain[idx + 1];
    if (next) {
      // まだ移行先が残っている → 次のサイトへ自動遷移
      location.href = `${next.targetOrigin}?migrate=1&idx=${idx + 1}#${encoded}`;
    } else {
      // チェーンの最後 = 全件移行完了
      alert("下書きデータの移行がすべて完了しました。");
      history.replaceState(null, "", location.origin + location.pathname);
      window.__migrationInProgress = false;
    }
  } catch (e) {
    console.error("draft migration failed", e);
    alert("下書きデータの移行中にエラーが発生しました。お手数ですが運営までご連絡ください。");
    history.replaceState(null, "", location.origin + location.pathname);
    window.__migrationInProgress = false;
  }
})();

/* ------------------------------------------------------------
   メイン処理
   ------------------------------------------------------------ */
(async () => {

  // 移行チェーンの転送中（次サイトへの中継のみ）は、
  // 通常のLIFF初期化・アプリ本処理を一切実行しない
  if (window.__migrationInProgress) return;

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
          // 現在のURLにidが無ければ検索パラメータを補い、hashも無ければ
          // 退避しておいた復号鍵のhashを補う（handleSharedViewはlocation.hash
          // を直接参照するため、アドレスバー側にも反映させておく）。
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

  /* ----- 旧ミニアプリからの下書き移行チェック（無ければ何もしない） -----
     ミニアプリからLIFFへの移行期間中のみ有効な処理。移行が完了したら
     この呼び出しと tryRestoreMigratedDraft() ごと削除して構わない。 */
  await tryRestoreMigratedDraft();

  /* ----- localStorage から下書き復元 ----- */
  try {
    const saved = localStorage.getItem(DRAFT_KEY);
    if (saved) restoreFormData(JSON.parse(saved));
  } catch (_) {}

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

  /* ----- 下書き保存 ----- */
  document.getElementById("draftBtn").addEventListener("click", () => {
    try {
      localStorage.setItem(DRAFT_KEY, JSON.stringify(collectFormData()));
      alert("下書きを保存しました。");
    } catch (_) {
      alert("下書きの保存に失敗しました。");
    }
  });

  /* ----- フォームクリア ----- */
  document.getElementById("clearBtn").addEventListener("click", () => {
    if (!confirm("入力内容をすべてクリアしますか？")) return;
    ["q1-1","q1-2","q2","q3Detail","q4","q5","q6Detail","q10","q11","q12","q13","q15"]
      .forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });
    document.querySelectorAll('input[type="radio"]').forEach(r => (r.checked = false));
    document.getElementById("q7").value = 3;
    document.getElementById("q8").value = 3;
    document.getElementById("q9").value = 3;
    toggleDetail("q3Detail", false);
    toggleDetail("q6Detail", false);
    try { localStorage.removeItem(DRAFT_KEY); } catch (_) {}
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
    try { localStorage.setItem(DRAFT_KEY, JSON.stringify(data)); } catch (_) {}

    document.getElementById("submitBtn").disabled = true;

    const modal = document.getElementById("shareModal");
    modal.classList.remove("hidden");
    modal.classList.add("show");
  });

  /* ----- 共有ボタン ----- */
  document.getElementById("shareBtn").addEventListener("click", async () => {
    const shareBtn = document.getElementById("shareBtn");
    const shareName = document.getElementById("shareName").value.trim();
    const data      = collectFormData();
    data._shareName = shareName;

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

      const base     = location.href.split("?")[0].split("#")[0];
      const shareURL = `${base}?id=${id}#${keyBase64}`;

      const previewMsg = shareName
        ? `${shareName}さんの婚活　自己開示QA part1の回答が届きました。\n回答をみる→${shareURL}`
        : `婚活　自己開示QA part1の回答が届きました。\n回答をみる→${shareURL}`;

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

})();

/* crypto.randomUUID が使えない古い環境用のフォールバック */
function fallbackUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
