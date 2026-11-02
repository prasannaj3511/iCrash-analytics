const nodemailer = require('nodemailer');
const { SMTP, APP_URL, ALERTS_ENABLED } = require('./config');

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enabled = () => SMTP.enabled;

let transport;
function getTransport() {
  transport ||= nodemailer.createTransport({
    host: SMTP.host, port: SMTP.port, secure: SMTP.secure, requireTLS: !SMTP.secure,
    auth: { user: SMTP.user, pass: SMTP.pass },
    connectionTimeout: 8000, greetingTimeout: 8000, socketTimeout: 15000,
  });
  return transport;
}

/** Never throws: returns { sent, reason? } so a mail outage can't break sign-ups or ingest. */
async function send(to, subject, html, text) {
  if (!SMTP.enabled) return { sent: false, reason: 'email is not configured' };
  try {
    await getTransport().sendMail({ from: `"${SMTP.fromName}" <${SMTP.from}>`, to, subject, html, text });
    return { sent: true };
  } catch (e) {
    console.error(`mail to ${to} failed: ${e.message}`);
    return { sent: false, reason: e.message };
  }
}

const shell = (title, body) => `<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:560px;margin:auto;color:#1b1f27">
<div style="padding:14px 0;font-weight:700;font-size:16px">⚡ iCrash Analytics</div>
<h2 style="margin:0 0 12px">${esc(title)}</h2>${body}
<hr style="border:0;border-top:1px solid #e3e6eb;margin:24px 0"><div style="color:#6b7380;font-size:12px">Sent by iCrash Analytics (${esc(APP_URL)})</div></div>`;
const button = (href, label) => `<p><a href="${esc(href)}" style="background:#5b5bd6;color:#fff;padding:9px 16px;border-radius:8px;text-decoration:none;display:inline-block">${esc(label)}</a></p>`;

function sendWelcome(user) {
  return send(user.email, 'Your iCrash Analytics account',
    shell(`Welcome, ${user.name || user.email}`, `<p>An account has been created for you on iCrash Analytics, where you can track crashes and errors from your frontend and backend apps.</p>
      <p><b>Email:</b> ${esc(user.email)}<br>Your administrator will share your temporary password separately. Please change it after your first sign-in (Account button).</p>${button(APP_URL, 'Open iCrash Analytics')}
      <p>New here? Open <b>User guide</b> in the sidebar for a five-minute setup.</p>`),
    `Welcome to iCrash Analytics. An account was created for ${user.email}. Your administrator will share the temporary password separately. Sign in at ${APP_URL} and change it after your first sign-in.`);
}

function sendPasswordReset(user) {
  return send(user.email, 'Your iCrash Analytics password was reset',
    shell('Your password was reset', `<p>An administrator reset the password for <b>${esc(user.email)}</b>. You were signed out on all devices. Your administrator will share the new temporary password with you separately.</p>${button(APP_URL, 'Sign in')}
      <p style="color:#6b7380;font-size:13px">If you weren't expecting this, contact your administrator.</p>`),
    `An administrator reset the password for ${user.email}. Sign in at ${APP_URL} with the new password they share with you.`);
}

function sendAddedToProject(member, project, addedBy) {
  const link = `${APP_URL}/#/p/${project.id}`;
  return send(member.email, `You were added to "${project.name}" on iCrash Analytics`,
    shell('You were added to a project', `<p><b>${esc(addedBy.name || addedBy.email)}</b> added you to the project <b>${esc(project.name)}</b>. You can view its issues, stats and setup details, and you will receive an email when a new issue appears.</p>${button(link, 'Open project')}`),
    `${addedBy.email} added you to the project "${project.name}". Open it: ${link}`);
}

/* ---- issue alerts: owner is emailed on a new issue or a regression, max 10 per project per hour ---- */
const sentLog = new Map();
const MAX_PER_HOUR = 10;
function allowAlert(projectId) {
  const now = Date.now();
  const arr = (sentLog.get(projectId) || []).filter((t) => now - t < 3600000);
  if (arr.length >= MAX_PER_HOUR) { sentLog.set(projectId, arr); return false; }
  arr.push(now); sentLog.set(projectId, arr); return true;
}

async function maybeAlert(project, ev) {
  if (!ALERTS_ENABLED || !SMTP.enabled || !project.owner_email) return;
  if (!(ev.isNew || ev.regressed) || ['info', 'debug'].includes(ev.level)) return;
  if (!allowAlert(project.id)) return;
  const kind = ev.regressed ? 'Regression' : 'New issue';
  const link = `${APP_URL}/#/i/${ev.issueId}`;
  const to = [...new Set([project.owner_email, ...(project.recipients || [])].map((e) => e.toLowerCase()))];
  const subject = `[${project.name}] ${kind}: ${ev.title}`.slice(0, 200);
  const html =
    shell(`${kind} in ${project.name}`, `<p style="font-weight:600;word-break:break-word">${esc(ev.title)}</p>
      <table style="font-size:14px;border-collapse:collapse"><tr><td style="color:#6b7380;padding:2px 12px 2px 0">Level</td><td>${esc(ev.level)}</td></tr>
      ${ev.culprit ? `<tr><td style="color:#6b7380;padding:2px 12px 2px 0">Where</td><td><code>${esc(ev.culprit)}</code></td></tr>` : ''}
      ${(ev.http?.path || ev.http?.url) ? `<tr><td style="color:#6b7380;padding:2px 12px 2px 0">API</td><td><code>${esc([ev.http.method, ev.http.path || ev.http.url].filter(Boolean).join(' '))}</code></td></tr>` : ''}
      ${ev.http?.status ? `<tr><td style="color:#6b7380;padding:2px 12px 2px 0">HTTP status</td><td><b>${esc(ev.http.status)}</b></td></tr>` : ''}
      ${ev.code ? `<tr><td style="color:#6b7380;padding:2px 12px 2px 0">Error code</td><td><code>${esc(ev.code)}</code></td></tr>` : ''}
      <tr><td style="color:#6b7380;padding:2px 12px 2px 0">Environment</td><td>${esc(ev.environment)}</td></tr>
      ${ev.release ? `<tr><td style="color:#6b7380;padding:2px 12px 2px 0">Release</td><td>${esc(ev.release)}</td></tr>` : ''}</table>
      ${ev.regressed ? '<p>This issue was marked resolved but has occurred again.</p>' : ''}${button(link, 'View issue')}`);
  const text = `${kind} in ${project.name}: ${ev.title}\nLevel: ${ev.level}\n${ev.http?.path ? `API: ${[ev.http.method, ev.http.path].filter(Boolean).join(' ')}\n` : ''}${ev.http?.status ? `HTTP status: ${ev.http.status}\n` : ''}${ev.code ? `Error code: ${ev.code}\n` : ''}Environment: ${ev.environment}\n${link}`;
  await Promise.allSettled(to.map((addr) => send(addr, subject, html, text)));
}

async function verify() {
  if (!SMTP.enabled) return { ok: false, reason: 'email is not configured' };
  try { await getTransport().verify(); return { ok: true }; } catch (e) { return { ok: false, reason: e.message }; }
}

module.exports = { enabled, send, sendAddedToProject, sendWelcome, sendPasswordReset, maybeAlert, verify };
