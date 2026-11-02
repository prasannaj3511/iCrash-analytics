// Sends a burst of sample errors to a project using the Node SDK.
// Usage: node examples/seed.js "<DSN from the project's Setup tab>"
const dsn = process.argv[2];
if (!dsn) {
  console.error('Usage: node examples/seed.js "<DSN>"   (copy the DSN from your project\'s Setup tab)');
  process.exit(1);
}

const icrash = require('../sdk/node');
icrash.init({ dsn, environment: 'staging', release: '0.9.0', autoCapture: false });

function chargeCard(order) { return order.payment.card.number; }
function loadUser(id) { throw new RangeError(`User ${id} not found`); }

(async () => {
  for (let i = 0; i < 8; i++) {
    icrash.setUser({ id: String(i % 4), email: `user${i % 4}@example.com` });
    try { chargeCard({}); } catch (e) { await icrash.captureException(e, { tags: { route: '/checkout' } }); }
    await new Promise((r) => setTimeout(r, 1100)); // the SDK drops identical errors fired <1s apart
    if (i % 3 === 0) try { loadUser(1000 + i); } catch (e) { await icrash.captureException(e); }
  }
  await icrash.captureMessage('Payment provider slow (>3s)', 'warning', { extra: { latencyMs: 3400 } });
  await icrash.flush();
  console.log('Sent sample events. Refresh the Issues tab.');
})();
