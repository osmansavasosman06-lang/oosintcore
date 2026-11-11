let mode = "login";
let pendingEmail = "";
const $ = id => document.getElementById(id);

function setMode(next) {
  mode = next;
  $("loginTab").classList.toggle("active", mode === "login");
  $("registerTab").classList.toggle("active", mode === "register");
  $("formTitle").textContent = mode === "login" ? "Tekrar hoş geldin." : "OSINTCORE'a katıl.";
  $("formSub").textContent = mode === "login" ? "Hesabına güvenli şekilde giriş yap." : "Yeni hesabını oluştur ve çalışma alanına eriş.";
  $("submitBtn").innerHTML = mode === "login" ? 'Giriş yap <span>→</span>' : 'Hesap oluştur <span>→</span>';
  $("password").autocomplete = mode === "login" ? "current-password" : "new-password";
  $("message").textContent = "";
  if (window.hcaptcha) { try { hcaptcha.reset(); } catch {} }
}

$("loginTab").addEventListener("click", () => setMode("login"));
$("registerTab").addEventListener("click", () => setMode("register"));

function captchaToken() {
  try { return window.hcaptcha ? hcaptcha.getResponse() : ""; } catch { return ""; }
}

$("authForm").addEventListener("submit", async e => {
  e.preventDefault();
  const token = captchaToken();
  if (!token) { $("message").textContent = "Lütfen hCaptcha doğrulamasını tamamla."; return; }
  $("submitBtn").disabled = true;
  $("message").textContent = "İşleniyor…";
  try {
    const response = await fetch(`/api/${mode}`, {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({email:$("email").value, password:$("password").value, captchaToken:token})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "İşlem tamamlanamadı.");
    if (data.requireVerification) {
      pendingEmail = data.email;
      $("authForm").classList.add("hidden");
      $("verifyForm").classList.remove("hidden");
      document.querySelector(".tabs").classList.add("hidden");
      $("formTitle").textContent = "E-postanı Doğrula";
      $("formSub").textContent = `${pendingEmail} adresine osintcore@gmail.com üzerinden gönderilen 6 haneli kodu gir.`;
      return;
    }
    await showWorkspace(data.user);
  } catch (err) {
    $("message").textContent = err.message;
    if (window.hcaptcha) { try { hcaptcha.reset(); } catch {} }
  } finally { $("submitBtn").disabled = false; }
});

$("verifyForm").addEventListener("submit", async e => {
  e.preventDefault();
  $("verifyBtn").disabled = true;
  $("verifyMessage").textContent = "Doğrulanıyor…";
  try {
    const response = await fetch("/api/verify-code", {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ email: pendingEmail, code: $("verifyCode").value })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Doğrulama başarısız.");
    await showWorkspace(data.user);
  } catch (err) {
    $("verifyMessage").textContent = err.message;
  } finally { $("verifyBtn").disabled = false; }
});

async function showWorkspace(user) {
  $("auth").classList.add("hidden");
  $("workspace").classList.remove("hidden");
  $("userEmail").textContent = user.email;
}

$("logout").addEventListener("click", async () => {
  await fetch("/api/logout", {method:"POST",credentials:"same-origin"});
  $("workspace").classList.add("hidden"); 
  $("auth").classList.remove("hidden");
  $("verifyForm").classList.add("hidden");
  $("authForm").classList.remove("hidden");
  document.querySelector(".tabs").classList.remove("hidden");
  $("password").value = ""; 
  setMode("login");
});

(async function init(){
  const sitekey = window.OSINTCORE_CONFIG?.hcaptchaSitekey || "";
  const captcha = $("hcaptcha");
  if (sitekey) captcha.setAttribute("data-sitekey", sitekey);
  else $("message").textContent = "Kurulum gerekli: .env dosyasına hCaptcha sitekey ve secret ekle.";
  try {
    const r = await fetch("/api/me", {credentials:"same-origin"});
    const d = await r.json();
    if (d.user) await showWorkspace(d.user);
  } catch {}
})();
