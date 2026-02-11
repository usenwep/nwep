'use strict';

const assert = require('assert');
const path = require('path');

let nwep;
try {
  nwep = require(path.join(__dirname, '..', 'lib'));
} catch (e) {
  console.error('Failed to load nwep addon:', e.message);
  console.error('Run "npm run build" first.');
  process.exit(1);
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  \u2713 ${name}`);
  } catch (e) {
    failed++;
    console.log(`  \u2717 ${name}`);
    console.log(`    ${e.message}`);
  }
}

/* === Core === */
console.log('\nCore');

test('version returns a string', () => {
  const ver = nwep.version();
  assert.strictEqual(typeof ver, 'string');
  assert.ok(ver.length > 0);
});

test('init succeeds', () => {
  nwep.init();
});

/* === Constants === */
console.log('\nConstants');

test('time constants are bigints', () => {
  assert.strictEqual(typeof nwep.NANOSECONDS, 'bigint');
  assert.strictEqual(typeof nwep.SECONDS, 'bigint');
  assert.strictEqual(nwep.NANOSECONDS, 1n);
  assert.strictEqual(nwep.SECONDS, 1000000000n);
});

test('protocol constants', () => {
  assert.strictEqual(typeof nwep.PROTO_VER, 'string');
  assert.strictEqual(typeof nwep.DEFAULT_PORT, 'number');
  assert.strictEqual(typeof nwep.ALPN, 'string');
});

test('crypto size constants', () => {
  assert.strictEqual(nwep.ED25519_PUBKEY_LEN, 32);
  assert.strictEqual(nwep.ED25519_SIG_LEN, 64);
  assert.strictEqual(nwep.NODEID_LEN, 32);
});

test('method constants are strings', () => {
  assert.strictEqual(typeof nwep.METHOD_READ, 'string');
  assert.strictEqual(typeof nwep.METHOD_WRITE, 'string');
});

test('status constants are strings', () => {
  assert.strictEqual(typeof nwep.STATUS_OK, 'string');
  assert.strictEqual(typeof nwep.STATUS_NOT_FOUND, 'string');
});

test('error code constants are negative numbers', () => {
  assert.ok(nwep.ERR_INTERNAL_NOMEM < 0);
  assert.ok(nwep.ERR_CRYPTO_INVALID_KEY < 0);
});

test('log level constants', () => {
  assert.strictEqual(typeof nwep.LOG_TRACE, 'number');
  assert.strictEqual(typeof nwep.LOG_ERROR, 'number');
  assert.ok(nwep.LOG_ERROR > nwep.LOG_TRACE);
});

test('handshake state constants', () => {
  assert.strictEqual(typeof nwep.CLIENT_STATE_INITIAL, 'number');
  assert.strictEqual(typeof nwep.SERVER_STATE_CONNECTED, 'number');
});

/* === Error === */
console.log('\nError');

test('strerror returns a string', () => {
  const s = nwep.strerror(nwep.ERR_INTERNAL_NOMEM);
  assert.strictEqual(typeof s, 'string');
  assert.ok(s.length > 0);
});

test('errIsFatal returns boolean', () => {
  assert.strictEqual(typeof nwep.errIsFatal(nwep.ERR_INTERNAL_NOMEM), 'boolean');
});

test('errCategory returns number', () => {
  const cat = nwep.errCategory(nwep.ERR_CRYPTO_INVALID_KEY);
  assert.strictEqual(typeof cat, 'number');
});

test('errCategoryStr returns string', () => {
  const s = nwep.errCategoryStr(nwep.ERR_CAT_CRYPTO);
  assert.strictEqual(typeof s, 'string');
});

test('errToStatus returns string', () => {
  const s = nwep.errToStatus(nwep.ERR_PROTO_INVALID_MESSAGE);
  assert.strictEqual(typeof s, 'string');
});

test('errorFormat returns formatted string', () => {
  const s = nwep.errorFormat({ code: nwep.ERR_INTERNAL_NOMEM, context: ['test'] });
  assert.strictEqual(typeof s, 'string');
  assert.ok(s.length > 0);
});

/* === Crypto === */
console.log('\nCrypto');

test('keypairGenerate produces valid keypair', () => {
  const kp = nwep.keypairGenerate();
  assert.ok(Buffer.isBuffer(kp.pubkey));
  assert.ok(Buffer.isBuffer(kp.privkey));
  assert.strictEqual(kp.pubkey.length, 32);
  assert.strictEqual(kp.privkey.length, 64);
});

test('keypairFromSeed is deterministic', () => {
  const seed = Buffer.alloc(32, 0x42);
  const kp1 = nwep.keypairFromSeed(seed);
  const kp2 = nwep.keypairFromSeed(seed);
  assert.ok(kp1.pubkey.equals(kp2.pubkey));
  assert.ok(kp1.privkey.equals(kp2.privkey));
});

test('keypairFromPrivkey round-trips', () => {
  const kp = nwep.keypairGenerate();
  const kp2 = nwep.keypairFromPrivkey(kp.privkey);
  assert.ok(kp.pubkey.equals(kp2.pubkey));
});

test('nodeidFromPubkey produces 32-byte NodeID', () => {
  const kp = nwep.keypairGenerate();
  const nid = nwep.nodeidFromPubkey(kp.pubkey);
  assert.ok(Buffer.isBuffer(nid));
  assert.strictEqual(nid.length, 32);
});

test('nodeidFromKeypair matches nodeidFromPubkey', () => {
  const kp = nwep.keypairGenerate();
  const nid1 = nwep.nodeidFromPubkey(kp.pubkey);
  const nid2 = nwep.nodeidFromKeypair(kp);
  assert.ok(nid1.equals(nid2));
});

test('nodeidEq works', () => {
  const kp = nwep.keypairGenerate();
  const nid = nwep.nodeidFromPubkey(kp.pubkey);
  assert.ok(nwep.nodeidEq(nid, nid));
  const other = nwep.nodeidFromPubkey(nwep.keypairGenerate().pubkey);
  assert.ok(!nwep.nodeidEq(nid, other));
});

test('nodeidIsZero works', () => {
  const zero = Buffer.alloc(32, 0);
  assert.ok(nwep.nodeidIsZero(zero));
  const kp = nwep.keypairGenerate();
  const nid = nwep.nodeidFromPubkey(kp.pubkey);
  assert.ok(!nwep.nodeidIsZero(nid));
});

test('sign and verify round-trip', () => {
  const kp = nwep.keypairGenerate();
  const msg = Buffer.from('hello world');
  const sig = nwep.sign(msg, kp);
  assert.ok(Buffer.isBuffer(sig));
  assert.strictEqual(sig.length, 64);
  assert.ok(nwep.verify(sig, msg, kp.pubkey));
});

test('verify rejects bad signature', () => {
  const kp = nwep.keypairGenerate();
  const msg = Buffer.from('hello world');
  const sig = nwep.sign(msg, kp);
  sig[0] ^= 0xff;
  assert.ok(!nwep.verify(sig, msg, kp.pubkey));
});

test('challenge generate/sign/verify', () => {
  const kp = nwep.keypairGenerate();
  const challenge = nwep.challengeGenerate();
  assert.ok(Buffer.isBuffer(challenge));
  assert.strictEqual(challenge.length, 32);
  const response = nwep.challengeSign(challenge, kp);
  assert.strictEqual(response.length, 64);
  assert.ok(nwep.challengeVerify(response, challenge, kp.pubkey));
});

test('randomBytes produces correct length', () => {
  const buf = nwep.randomBytes(16);
  assert.ok(Buffer.isBuffer(buf));
  assert.strictEqual(buf.length, 16);
});

test('shamirSplit and shamirCombine round-trip', () => {
  const secret = nwep.randomBytes(32);
  const shares = nwep.shamirSplit(secret, 5, 3);
  assert.strictEqual(shares.length, 5);
  const recovered = nwep.shamirCombine(shares.slice(0, 3));
  assert.ok(secret.equals(recovered));
});

test('traceIdGenerate returns 16 bytes', () => {
  const id = nwep.traceIdGenerate();
  assert.strictEqual(id.length, 16);
});

test('requestIdGenerate returns 16 bytes', () => {
  const id = nwep.requestIdGenerate();
  assert.strictEqual(id.length, 16);
});

/* === Encoding === */
console.log('\nEncoding');

test('base58 encode/decode round-trip', () => {
  const data = Buffer.from('hello');
  const encoded = nwep.base58Encode(data);
  assert.strictEqual(typeof encoded, 'string');
  const decoded = nwep.base58Decode(encoded);
  assert.ok(data.equals(decoded));
});

test('base64 encode/decode round-trip', () => {
  const data = Buffer.from('hello world');
  const encoded = nwep.base64Encode(data);
  assert.strictEqual(typeof encoded, 'string');
  const decoded = nwep.base64Decode(encoded);
  assert.ok(data.equals(decoded));
});

test('uint32be put/get round-trip', () => {
  const buf = nwep.putUint32be(0xdeadbeef);
  assert.strictEqual(buf.length, 4);
  assert.strictEqual(nwep.getUint32be(buf), 0xdeadbeef);
});

test('uint16be put/get round-trip', () => {
  const buf = nwep.putUint16be(0x1234);
  assert.strictEqual(buf.length, 2);
  assert.strictEqual(nwep.getUint16be(buf), 0x1234);
});

/* === Address === */
console.log('\nAddress');

test('addrEncode/addrDecode round-trip', () => {
  const addr = {
    ip: Buffer.alloc(16, 0),
    nodeid: nwep.nodeidFromPubkey(nwep.keypairGenerate().pubkey),
    port: nwep.DEFAULT_PORT,
  };
  // Set IPv4 127.0.0.1 mapped to IPv6
  addr.ip[10] = 0xff;
  addr.ip[11] = 0xff;
  addr.ip[12] = 127;
  addr.ip[15] = 1;

  const encoded = nwep.addrEncode(addr);
  assert.strictEqual(typeof encoded, 'string');
  const decoded = nwep.addrDecode(encoded);
  assert.ok(addr.ip.equals(decoded.ip));
  assert.ok(addr.nodeid.equals(decoded.nodeid));
  // addr_encode/decode only encodes IP+NodeID; port defaults to DEFAULT_PORT
  assert.strictEqual(decoded.port, nwep.DEFAULT_PORT);
});

/* === Message === */
console.log('\nMessage');

test('msgEncode/msgDecode round-trip', () => {
  const msg = {
    type: nwep.MSG_REQUEST,
    headers: [
      { name: 'method', value: Buffer.from('READ') },
      { name: 'path', value: Buffer.from('/test') },
    ],
    body: Buffer.from('hello'),
  };
  const encoded = nwep.msgEncode(msg);
  assert.ok(Buffer.isBuffer(encoded));
  const decoded = nwep.msgDecode(encoded);
  assert.strictEqual(decoded.type, nwep.MSG_REQUEST);
  assert.strictEqual(decoded.headers.length, 2);
});

test('methodIsValid works', () => {
  assert.ok(nwep.methodIsValid(nwep.METHOD_READ));
  assert.ok(!nwep.methodIsValid('INVALID'));
});

test('statusIsValid works', () => {
  assert.ok(nwep.statusIsValid(nwep.STATUS_OK));
  assert.ok(!nwep.statusIsValid('invalid_status'));
});

test('statusIsSuccess and statusIsError', () => {
  assert.ok(nwep.statusIsSuccess(nwep.STATUS_OK));
  assert.ok(!nwep.statusIsError(nwep.STATUS_OK));
  assert.ok(nwep.statusIsError(nwep.STATUS_INTERNAL_ERROR));
});

/* === Logging === */
console.log('\nLogging');

test('logLevelStr returns string', () => {
  const s = nwep.logLevelStr(nwep.LOG_INFO);
  assert.strictEqual(typeof s, 'string');
});

test('logGetLevel/logSetLevel round-trip', () => {
  const original = nwep.logGetLevel();
  nwep.logSetLevel(nwep.LOG_WARN);
  assert.strictEqual(nwep.logGetLevel(), nwep.LOG_WARN);
  nwep.logSetLevel(original);
});

test('logFormatJson returns JSON string', () => {
  const s = nwep.logFormatJson({
    level: nwep.LOG_INFO,
    component: 'test',
    message: 'hello',
  });
  assert.strictEqual(typeof s, 'string');
  assert.ok(s.length > 0);
});

/* === Identity === */
console.log('\nIdentity');

test('recoveryAuthorityNew creates RA', () => {
  const ra = nwep.recoveryAuthorityNew();
  assert.ok(ra.keypair);
  assert.ok(Buffer.isBuffer(ra.keypair.pubkey));
  assert.strictEqual(ra.initialized, true);
});

test('recoveryAuthorityGetPubkey returns buffer', () => {
  const ra = nwep.recoveryAuthorityNew();
  const pk = nwep.recoveryAuthorityGetPubkey(ra);
  assert.ok(Buffer.isBuffer(pk));
  assert.strictEqual(pk.length, 32);
});

test('managedIdentityNew creates identity', () => {
  const kp = nwep.keypairGenerate();
  const now = BigInt(Date.now()) * 1000000n;
  const id = nwep.managedIdentityNew(kp, now);
  assert.ok(Buffer.isBuffer(id.nodeid));
  assert.strictEqual(id.nodeid.length, 32);
  assert.strictEqual(typeof id.keyCount, 'number');
  assert.ok(id.keyCount >= 1);
  assert.strictEqual(id.revoked, false);
});

test('managedIdentityNew with recovery authority', () => {
  const kp = nwep.keypairGenerate();
  const ra = nwep.recoveryAuthorityNew();
  const now = BigInt(Date.now()) * 1000000n;
  const id = nwep.managedIdentityNew(kp, now, ra);
  assert.ok(id.hasRecovery);
  assert.ok(Buffer.isBuffer(id.recoveryPubkey));
});

test('managedIdentityIsRevoked returns boolean', () => {
  const kp = nwep.keypairGenerate();
  const now = BigInt(Date.now()) * 1000000n;
  const id = nwep.managedIdentityNew(kp, now);
  assert.strictEqual(nwep.managedIdentityIsRevoked(id), false);
});

/* === Handshake === */
console.log('\nHandshake');

test('handshakeClientInit creates handle', () => {
  const kp = nwep.keypairGenerate();
  const h = nwep.handshakeClientInit(kp);
  assert.ok(h != null);
  nwep.handshakeFree(h);
});

test('handshakeServerInit creates handle', () => {
  const kp = nwep.keypairGenerate();
  const h = nwep.handshakeServerInit(kp);
  assert.ok(h != null);
  nwep.handshakeFree(h);
});

test('clientStateStr and serverStateStr', () => {
  assert.strictEqual(typeof nwep.clientStateStr(nwep.CLIENT_STATE_INITIAL), 'string');
  assert.strictEqual(typeof nwep.serverStateStr(nwep.SERVER_STATE_INITIAL), 'string');
});

/* === Role === */
console.log('\nRole');

test('roleFromStr/roleToStr round-trip', () => {
  const role = nwep.roleFromStr(nwep.ROLE_STR_LOG_SERVER);
  assert.strictEqual(role, nwep.ROLE_LOG_SERVER);
  const str = nwep.roleToStr(nwep.ROLE_LOG_SERVER);
  assert.strictEqual(str, nwep.ROLE_STR_LOG_SERVER);
});

/* === Summary === */
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
