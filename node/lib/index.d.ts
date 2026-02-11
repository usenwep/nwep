/// <reference types="node" />

export type ServerHandle = unknown;
export type ClientHandle = unknown;
export type ConnHandle = unknown;
export type StreamHandle = unknown;
export type HandshakeHandle = unknown;
export type AnchorSetHandle = unknown;
export type TrustStoreHandle = unknown;
export type IdentityCacheHandle = unknown;
export type LogServerPoolHandle = unknown;

export interface Keypair {
  pubkey: Buffer;
  privkey: Buffer;
}

export interface ShamirShare {
  index: number;
  data: Buffer;
}

export interface NwepAddr {
  ip: Buffer;
  nodeid: Buffer;
  port: number;
}

export interface NwepUrl {
  addr: NwepAddr;
  path: string;
}

export interface MsgHeader {
  name: string;
  value: Buffer;
}

export interface NwepMsg {
  type: number;
  headers: MsgHeader[];
  body: Buffer;
}

export interface LogEntry {
  level: number;
  component: string;
  message: string;
}

export interface ManagedIdentityKey {
  keypair: Keypair;
  active: boolean;
  activatedAt: bigint;
  expiresAt: bigint;
}

export interface ManagedIdentity {
  nodeid: Buffer;
  keyCount: number;
  hasRecovery: boolean;
  revoked: boolean;
  recoveryPubkey?: Buffer;
  keys: ManagedIdentityKey[];
}

export interface RecoveryAuthority {
  keypair: Keypair;
  initialized: boolean;
}

export interface Identity {
  pubkey: Buffer;
  nodeid: Buffer;
}

export interface MerkleEntry {
  type: number;
  timestamp: bigint;
  nodeid: Buffer;
  pubkey: Buffer;
  prevPubkey: Buffer;
  recoveryPubkey: Buffer;
  signature: Buffer;
}

export interface MerkleProof {
  index: bigint;
  logSize: bigint;
  leafHash: Buffer;
  siblings: Buffer[];
  depth: number;
}

export interface BlsKeypair {
  pubkey: Buffer;
  privkey: Buffer;
}

export interface Checkpoint {
  epoch: bigint;
  timestamp: bigint;
  merkleRoot: Buffer;
  logSize: bigint;
  signature: Buffer;
  signers: Buffer[];
  numSigners: number;
}

export interface NwepResponse {
  status: string;
  statusDetails?: string;
  body?: Buffer;
}

export interface CachedIdentity {
  nodeid: Buffer;
  pubkey: Buffer;
  logIndex: bigint;
  verifiedAt: bigint;
  expiresAt: bigint;
}

export interface PoolServer {
  url: string;
  health: number;
  consecutiveFailures: number;
  lastSuccess: bigint;
  lastFailure: bigint;
}

export interface HandshakeParams {
  maxStreams?: number;
  maxMessageSize?: number;
  compression?: string;
  role?: string;
}

export interface ServerSettings {
  maxStreams?: number;
  maxMessageSize?: number;
  timeoutMs?: number;
}

export interface ClientSettings {
  maxStreams?: number;
  maxMessageSize?: number;
  timeoutMs?: number;
}

export interface TrustSettings {
  stalenessWarningNs?: bigint;
  stalenessRejectNs?: bigint;
  identityCacheTtl?: bigint;
  anchorThreshold?: number;
}

export interface IdentityCacheSettings {
  capacity?: number;
  ttlNs?: bigint;
}

export interface ServerNewResult {
  server: ServerHandle;
  keypair: Keypair;
}

export interface ClientNewResult {
  client: ClientHandle;
  keypair: Keypair;
}

export interface ServerWriteResult {
  data: Buffer;
  path: Buffer;
}

export interface ErrorFormatInput {
  code: number;
  context?: string[];
}

export const NANOSECONDS: bigint;
export const MICROSECONDS: bigint;
export const MILLISECONDS: bigint;
export const SECONDS: bigint;

export const PROTO_VER: string;
export const ALPN: string;
export const ALPN_LEN: number;
export const DEFAULT_PORT: number;

export const DEFAULT_MAX_MESSAGE_SIZE: number;
export const MAX_HEADERS: number;
export const MAX_HEADER_SIZE: number;
export const DEFAULT_MAX_STREAMS: number;
export const DEFAULT_TIMEOUT: bigint;

export const ED25519_PUBKEY_LEN: number;
export const ED25519_PRIVKEY_LEN: number;
export const ED25519_SIG_LEN: number;
export const NODEID_LEN: number;
export const CHALLENGE_LEN: number;
export const REQUEST_ID_LEN: number;
export const TRACE_ID_LEN: number;

export const MSG_REQUEST: number;
export const MSG_RESPONSE: number;
export const MSG_STREAM: number;
export const MSG_NOTIFY: number;

export const METHOD_READ: string;
export const METHOD_WRITE: string;
export const METHOD_UPDATE: string;
export const METHOD_DELETE: string;
export const METHOD_CONNECT: string;
export const METHOD_AUTHENTICATE: string;
export const METHOD_HEARTBEAT: string;

export const STATUS_OK: string;
export const STATUS_CREATED: string;
export const STATUS_ACCEPTED: string;
export const STATUS_NO_CONTENT: string;
export const STATUS_BAD_REQUEST: string;
export const STATUS_UNAUTHORIZED: string;
export const STATUS_FORBIDDEN: string;
export const STATUS_NOT_FOUND: string;
export const STATUS_CONFLICT: string;
export const STATUS_RATE_LIMITED: string;
export const STATUS_INTERNAL_ERROR: string;
export const STATUS_UNAVAILABLE: string;

export const ERR_CONFIG_FILE_NOT_FOUND: number;
export const ERR_CONFIG_PARSE_ERROR: number;
export const ERR_CONFIG_INVALID_VALUE: number;
export const ERR_CONFIG_MISSING_REQUIRED: number;
export const ERR_CONFIG_VALIDATION_FAILED: number;

export const ERR_NETWORK_CONN_FAILED: number;
export const ERR_NETWORK_CONN_CLOSED: number;
export const ERR_NETWORK_TIMEOUT: number;
export const ERR_NETWORK_ADDR_IN_USE: number;
export const ERR_NETWORK_ADDR_INVALID: number;
export const ERR_NETWORK_SOCKET: number;
export const ERR_NETWORK_TLS: number;
export const ERR_NETWORK_QUIC: number;
export const ERR_NETWORK_NO_SERVERS: number;

export const ERR_CRYPTO_KEY_GEN_FAILED: number;
export const ERR_CRYPTO_SIGN_FAILED: number;
export const ERR_CRYPTO_VERIFY_FAILED: number;
export const ERR_CRYPTO_HASH_FAILED: number;
export const ERR_CRYPTO_INVALID_KEY: number;
export const ERR_CRYPTO_INVALID_SIG: number;
export const ERR_CRYPTO_ENCRYPT_FAILED: number;
export const ERR_CRYPTO_DECRYPT_FAILED: number;
export const ERR_CRYPTO_KEY_LOAD_FAILED: number;
export const ERR_CRYPTO_KEY_SAVE_FAILED: number;
export const ERR_CRYPTO_CERT_ERROR: number;
export const ERR_CRYPTO_PUBKEY_MISMATCH: number;
export const ERR_CRYPTO_NODEID_MISMATCH: number;
export const ERR_CRYPTO_CHALLENGE_FAILED: number;
export const ERR_CRYPTO_SERVER_SIG_INVALID: number;
export const ERR_CRYPTO_CLIENT_SIG_INVALID: number;
export const ERR_CRYPTO_AUTH_TIMEOUT: number;

export const ERR_PROTO_INVALID_MESSAGE: number;
export const ERR_PROTO_INVALID_METHOD: number;
export const ERR_PROTO_INVALID_HEADER: number;
export const ERR_PROTO_MSG_TOO_LARGE: number;
export const ERR_PROTO_STREAM_ERROR: number;
export const ERR_PROTO_INVALID_STATUS: number;
export const ERR_PROTO_CONNECT_REQUIRED: number;
export const ERR_PROTO_TOO_MANY_HEADERS: number;
export const ERR_PROTO_HEADER_TOO_LARGE: number;
export const ERR_PROTO_0RTT_REJECTED: number;
export const ERR_PROTO_MISSING_HEADER: number;
export const ERR_PROTO_ROLE_MISMATCH: number;
export const ERR_PROTO_UNAUTHORIZED: number;
export const ERR_PROTO_PATH_NOT_FOUND: number;
export const ERR_PROTO_VERSION_MISMATCH: number;

export const ERR_IDENTITY_INVALID_NODEID: number;
export const ERR_IDENTITY_INVALID_ADDR: number;
export const ERR_IDENTITY_AUTH_FAILED: number;
export const ERR_IDENTITY_CHALLENGE_EXPIRED: number;
export const ERR_IDENTITY_NO_RECOVERY: number;
export const ERR_IDENTITY_RECOVERY_MISMATCH: number;
export const ERR_IDENTITY_INVALID_SHARE: number;
export const ERR_IDENTITY_SHARE_COMBINE: number;
export const ERR_IDENTITY_INVALID_THRESHOLD: number;
export const ERR_IDENTITY_ROTATION_IN_PROGRESS: number;
export const ERR_IDENTITY_KEY_MISMATCH: number;
export const ERR_IDENTITY_REVOKED: number;

export const ERR_STORAGE_FILE_NOT_FOUND: number;
export const ERR_STORAGE_READ_ERROR: number;
export const ERR_STORAGE_WRITE_ERROR: number;
export const ERR_STORAGE_PERMISSION: number;
export const ERR_STORAGE_DISK_FULL: number;
export const ERR_STORAGE_KEY_NOT_FOUND: number;
export const ERR_STORAGE_INDEX_OUT_OF_RANGE: number;
export const ERR_STORAGE_CORRUPTED: number;

export const ERR_TRUST_PARSE_ERROR: number;
export const ERR_TRUST_INVALID_ENTRY: number;
export const ERR_TRUST_INVALID_SIG: number;
export const ERR_TRUST_QUORUM_NOT_REACHED: number;
export const ERR_TRUST_INVALID_PROOF: number;
export const ERR_TRUST_ENTRY_NOT_FOUND: number;
export const ERR_TRUST_CHECKPOINT_STALE: number;
export const ERR_TRUST_ANCHOR_UNKNOWN: number;
export const ERR_TRUST_DUPLICATE_BINDING: number;
export const ERR_TRUST_NODE_NOT_FOUND: number;
export const ERR_TRUST_ALREADY_REVOKED: number;
export const ERR_TRUST_INVALID_AUTH: number;
export const ERR_TRUST_UNAUTHORIZED: number;
export const ERR_TRUST_TYPE_NOT_ALLOWED: number;
export const ERR_TRUST_KEY_MISMATCH: number;
export const ERR_TRUST_STORAGE: number;
export const ERR_TRUST_LOG_CORRUPTED: number;
export const ERR_TRUST_EQUIVOCATION: number;

export const ERR_INTERNAL_UNKNOWN: number;
export const ERR_INTERNAL_NOT_IMPLEMENTED: number;
export const ERR_INTERNAL_INVALID_STATE: number;
export const ERR_INTERNAL_NULL_PTR: number;
export const ERR_INTERNAL_NOMEM: number;
export const ERR_INTERNAL_INVALID_ARG: number;
export const ERR_INTERNAL_CALLBACK_FAILURE: number;
export const ERR_INTERNAL_NOBUF: number;

export const ERR_FATAL_THRESHOLD: number;
export const ERR_CONTEXT_MAX: number;

export const FRAME_HEADER_SIZE: number;
export const MSG_TYPE_SIZE: number;

export const HDR_METHOD: string;
export const HDR_PATH: string;
export const HDR_VERSION: string;
export const HDR_STATUS: string;
export const HDR_REQUEST_ID: string;
export const HDR_CLIENT_ID: string;
export const HDR_SERVER_ID: string;
export const HDR_CHALLENGE: string;
export const HDR_CHALLENGE_RESPONSE: string;
export const HDR_SERVER_CHALLENGE: string;
export const HDR_AUTH_RESPONSE: string;
export const HDR_MAX_STREAMS: string;
export const HDR_MAX_MESSAGE_SIZE: string;
export const HDR_COMPRESSION: string;
export const HDR_ROLES: string;
export const HDR_TRANSCRIPT_SIG: string;
export const HDR_STATUS_DETAILS: string;
export const HDR_RETRY_AFTER: string;
export const HDR_TRACE_ID: string;
export const HDR_EVENT: string;
export const HDR_NOTIFY_ID: string;

export const BASE58_ADDR_LEN: number;
export const URL_MAX_LEN: number;

export const SHAMIR_MAX_SHARES: number;
export const SHAMIR_MIN_THRESHOLD: number;

export const KEY_OVERLAP_SECONDS: number;
export const MAX_ACTIVE_KEYS: number;

export const LOG_ENTRY_MAX_SIZE: number;
export const MERKLE_PROOF_MAX_DEPTH: number;
export const LOG_ENTRY_KEY_BINDING: number;
export const LOG_ENTRY_KEY_ROTATION: number;
export const LOG_ENTRY_REVOCATION: number;
export const LOG_ENTRY_ANCHOR_CHANGE: number;

export const BLS_PUBKEY_LEN: number;
export const BLS_PRIVKEY_LEN: number;
export const BLS_SIG_LEN: number;
export const CHECKPOINT_DST: string;
export const DEFAULT_ANCHOR_THRESHOLD: number;
export const MAX_ANCHORS: number;
export const DEFAULT_EPOCH_INTERVAL: bigint;

export const STALENESS_WARNING_NS: bigint;
export const STALENESS_REJECT_NS: bigint;
export const IDENTITY_CACHE_TTL: bigint;
export const MAX_CHECKPOINTS: number;
export const STALENESS_FRESH: number;
export const STALENESS_WARNING: number;
export const STALENESS_REJECT: number;

export const ROLE_REGULAR: number;
export const ROLE_LOG_SERVER: number;
export const ROLE_ANCHOR: number;
export const ROLE_STR_REGULAR: string;
export const ROLE_STR_LOG_SERVER: string;
export const ROLE_STR_ANCHOR: string;

export const CACHE_DEFAULT_CAPACITY: number;
export const CACHE_DEFAULT_TTL_NS: bigint;
export const POOL_MAX_SERVERS: number;
export const POOL_HEALTH_CHECK_FAILURES: number;
export const POOL_ROUND_ROBIN: number;
export const POOL_RANDOM: number;
export const SERVER_HEALTHY: number;
export const SERVER_UNHEALTHY: number;

export const NOTIFY_ID_LEN: number;

export const CLIENT_STATE_INITIAL: number;
export const CLIENT_STATE_TLS_HANDSHAKE: number;
export const CLIENT_STATE_SEND_CONNECT: number;
export const CLIENT_STATE_WAIT_CONNECT_RESP: number;
export const CLIENT_STATE_SEND_AUTHENTICATE: number;
export const CLIENT_STATE_WAIT_AUTH_RESP: number;
export const CLIENT_STATE_CONNECTED: number;
export const CLIENT_STATE_ERROR: number;

export const SERVER_STATE_INITIAL: number;
export const SERVER_STATE_TLS_HANDSHAKE: number;
export const SERVER_STATE_AWAITING_CONNECT: number;
export const SERVER_STATE_AWAITING_CLIENT_AUTH: number;
export const SERVER_STATE_CONNECTED: number;
export const SERVER_STATE_ERROR: number;

export const LOG_TRACE: number;
export const LOG_DEBUG: number;
export const LOG_INFO: number;
export const LOG_WARN: number;
export const LOG_ERROR: number;

export const ERR_CAT_NONE: number;
export const ERR_CAT_CONFIG: number;
export const ERR_CAT_NETWORK: number;
export const ERR_CAT_CRYPTO: number;
export const ERR_CAT_PROTOCOL: number;
export const ERR_CAT_IDENTITY: number;
export const ERR_CAT_STORAGE: number;
export const ERR_CAT_TRUST: number;
export const ERR_CAT_INTERNAL: number;

export function init(): void;
export function version(): string;

export function strerror(code: number): string;
export function errIsFatal(code: number): boolean;
export function errCategory(code: number): number;
export function errCategoryStr(category: number): string;
export function errToStatus(code: number): string;
export function errorFormat(input: ErrorFormatInput): string;

export function keypairGenerate(): Keypair;
export function keypairFromSeed(seed: Buffer): Keypair;
export function keypairFromPrivkey(privkey: Buffer): Keypair;
export function nodeidFromPubkey(pubkey: Buffer): Buffer;
export function nodeidFromKeypair(keypair: Keypair): Buffer;
export function nodeidEq(a: Buffer, b: Buffer): boolean;
export function nodeidIsZero(nodeid: Buffer): boolean;
export function sign(message: Buffer, keypair: Keypair): Buffer;
export function verify(
  signature: Buffer,
  message: Buffer,
  pubkey: Buffer,
): boolean;
export function challengeGenerate(): Buffer;
export function challengeSign(challenge: Buffer, keypair: Keypair): Buffer;
export function challengeVerify(
  response: Buffer,
  challenge: Buffer,
  pubkey: Buffer,
): boolean;
export function randomBytes(length: number): Buffer;
export function shamirSplit(
  secret: Buffer,
  numShares: number,
  threshold: number,
): ShamirShare[];
export function shamirCombine(shares: ShamirShare[]): Buffer;
export function traceIdGenerate(): Buffer;
export function requestIdGenerate(): Buffer;

export function base58Encode(data: Buffer): string;
export function base58Decode(encoded: string): Buffer;
export function base64Encode(data: Buffer): string;
export function base64Decode(encoded: string): Buffer;
export function putUint32be(value: number): Buffer;
export function getUint32be(data: Buffer): number;
export function putUint16be(value: number): Buffer;
export function getUint16be(data: Buffer): number;

export function addrEncode(addr: NwepAddr): string;
export function addrDecode(encoded: string): NwepAddr;
export function urlParse(url: string): NwepUrl;
export function urlFormat(url: NwepUrl): string;
export function addrSetIpv4(addr: NwepAddr, ipv4: number): NwepAddr;
export function addrSetIpv6(addr: NwepAddr, ipv6: Buffer): NwepAddr;

export function msgEncode(msg: NwepMsg): Buffer;
export function msgDecode(data: Buffer): NwepMsg;
export function msgDecodeHeader(data: Buffer): number;
export function msgEncodeLen(msg: NwepMsg): number;
export function requestBuild(
  method: string,
  path: string,
  body?: Buffer | null,
  headers?: MsgHeader[],
): Buffer;
export function responseBuild(
  status: string,
  details?: string | null,
  body?: Buffer | null,
  headers?: MsgHeader[],
): Buffer;
export function methodIsValid(method: string): boolean;
export function methodIsIdempotent(method: string): boolean;
export function methodAllowed0rtt(method: string): boolean;
export function statusIsValid(status: string): boolean;
export function statusIsSuccess(status: string): boolean;
export function statusIsError(status: string): boolean;

export function handshakeClientInit(
  keypair: Keypair,
  expectedNodeid?: Buffer | null,
): HandshakeHandle;
export function handshakeServerInit(keypair: Keypair): HandshakeHandle;
export function handshakeFree(handle: HandshakeHandle): void;
export function handshakeSetParams(
  handle: HandshakeHandle,
  params: HandshakeParams,
): void;
export function clientStateStr(state: number): string;
export function serverStateStr(state: number): string;

export function logLevelStr(level: number): string;
export function logSetLevel(level: number): void;
export function logGetLevel(): number;
export function logSetJson(enabled: boolean): void;
export function logSetStderr(enabled: boolean): void;
export function logWrite(
  level: number,
  component: string,
  message: string,
): void;
export function logFormatJson(entry: LogEntry): string;

export function recoveryAuthorityNew(): RecoveryAuthority;
export function recoveryAuthorityGetPubkey(
  authority: RecoveryAuthority,
): Buffer | null;
export function managedIdentityNew(
  keypair: Keypair,
  now: bigint,
  recoveryAuthority?: RecoveryAuthority | null,
): ManagedIdentity;
export function managedIdentityRotate(): never;
export function managedIdentityIsRevoked(identity: ManagedIdentity): boolean;

export function serverNew(settings?: ServerSettings): ServerNewResult;
export function serverFree(server: ServerHandle): void;
export function serverRead(
  server: ServerHandle,
  path: Buffer,
  data: Buffer,
  timestamp: bigint,
): void;
export function serverWrite(
  server: ServerHandle,
  timestamp: bigint,
): ServerWriteResult | null;
export function serverHandleExpiry(
  server: ServerHandle,
  timestamp: bigint,
): void;
export function serverGetExpiry(server: ServerHandle): bigint;
export function serverClose(server: ServerHandle): void;

export function clientNew(settings?: ClientSettings): ClientNewResult;
export function clientFree(client: ClientHandle): void;
export function clientConnect(
  client: ClientHandle,
  url: string,
  timestamp: bigint,
): void;
export function clientRead(
  client: ClientHandle,
  data: Buffer,
  timestamp: bigint,
): void;
export function clientWrite(
  client: ClientHandle,
  timestamp: bigint,
): Buffer | null;
export function clientHandleExpiry(
  client: ClientHandle,
  timestamp: bigint,
): void;
export function clientGetExpiry(client: ClientHandle): bigint;
export function clientClose(client: ClientHandle): void;
export function clientGetConn(client: ClientHandle): ConnHandle | null;

export function connGetPeerIdentity(conn: ConnHandle): Identity;
export function connGetLocalIdentity(conn: ConnHandle): Identity;
export function connGetRole(conn: ConnHandle): string | null;
export function connClose(conn: ConnHandle, errorCode: number): void;

export function streamRespond(
  stream: StreamHandle,
  response: NwepResponse,
): void;
export function streamWrite(stream: StreamHandle, data: Buffer): number;
export function streamEnd(stream: StreamHandle): void;
export function streamClose(stream: StreamHandle, errorCode: number): void;
export function streamGetId(stream: StreamHandle): number;
export function streamIsServerInitiated(stream: StreamHandle): boolean;
export function streamGetConn(stream: StreamHandle): ConnHandle | null;

export function merkleEntryEncode(entry: MerkleEntry): Buffer;
export function merkleEntryDecode(data: Buffer): MerkleEntry;
export function merkleLeafHash(entry: MerkleEntry): Buffer;
export function merkleNodeHash(left: Buffer, right: Buffer): Buffer;
export function merkleProofVerify(proof: MerkleProof, root: Buffer): boolean;
export function merkleProofEncode(proof: MerkleProof): Buffer;
export function merkleProofDecode(data: Buffer): MerkleProof;

export function blsKeypairGenerate(): BlsKeypair;
export function blsKeypairFromSeed(seed: Buffer): BlsKeypair;
export function blsSign(keypair: BlsKeypair, message: Buffer): Buffer;
export function blsVerify(
  pubkey: Buffer,
  signature: Buffer,
  message: Buffer,
): boolean;
export function blsAggregateSigs(signatures: Buffer[]): Buffer;
export function blsVerifyAggregate(
  pubkeys: Buffer[],
  signature: Buffer,
  message: Buffer,
): boolean;
export function anchorSetNew(threshold: number): AnchorSetHandle;
export function anchorSetFree(set: AnchorSetHandle): void;
export function anchorSetAdd(
  set: AnchorSetHandle,
  pubkey: Buffer,
  builtin: boolean,
): void;
export function anchorSetRemove(
  set: AnchorSetHandle,
  pubkey: Buffer,
): void;
export function anchorSetSize(set: AnchorSetHandle): number;
export function anchorSetThreshold(set: AnchorSetHandle): number;
export function anchorSetContains(
  set: AnchorSetHandle,
  pubkey: Buffer,
): boolean;
export function checkpointNew(
  epoch: bigint,
  timestamp: bigint,
  merkleRoot: Buffer,
  logSize: bigint,
): Checkpoint;
export function checkpointEncode(checkpoint: Checkpoint): Buffer;
export function checkpointDecode(data: Buffer): Checkpoint;

export function trustSettingsDefault(): TrustSettings;
export function trustStoreNew(settings?: TrustSettings): TrustStoreHandle;
export function trustStoreFree(store: TrustStoreHandle): void;
export function trustStoreAddAnchor(
  store: TrustStoreHandle,
  pubkey: Buffer,
  builtin: boolean,
): void;
export function trustStoreRemoveAnchor(
  store: TrustStoreHandle,
  pubkey: Buffer,
): void;
export function trustStoreAddCheckpoint(
  store: TrustStoreHandle,
  checkpoint: Checkpoint,
): void;
export function trustStoreGetLatestCheckpoint(
  store: TrustStoreHandle,
): Checkpoint | null;
export function trustStoreCheckpointCount(store: TrustStoreHandle): number;
export function trustStoreCheckStaleness(
  store: TrustStoreHandle,
  now: bigint,
): number;
export function trustStoreGetStalenessAge(
  store: TrustStoreHandle,
  now: bigint,
): bigint;

export function roleFromStr(role: string): number;
export function roleToStr(role: number): string;

export function identityCacheNew(
  settings?: IdentityCacheSettings,
): IdentityCacheHandle;
export function identityCacheFree(cache: IdentityCacheHandle): void;
export function identityCacheLookup(
  cache: IdentityCacheHandle,
  nodeid: Buffer,
  now: bigint,
): CachedIdentity | null;
export function identityCacheStore(
  cache: IdentityCacheHandle,
  nodeid: Buffer,
  pubkey: Buffer,
  logIndex: bigint,
  now: bigint,
): void;
export function identityCacheInvalidate(
  cache: IdentityCacheHandle,
  nodeid: Buffer,
): void;
export function identityCacheClear(cache: IdentityCacheHandle): void;
export function identityCacheSize(cache: IdentityCacheHandle): number;
export function identityCacheCapacity(cache: IdentityCacheHandle): number;

export function logServerPoolNew(
  settings?: unknown,
): LogServerPoolHandle;
export function logServerPoolFree(pool: LogServerPoolHandle): void;
export function logServerPoolAdd(
  pool: LogServerPoolHandle,
  url: string,
): void;
export function logServerPoolRemove(
  pool: LogServerPoolHandle,
  url: string,
): void;
export function logServerPoolSelect(pool: LogServerPoolHandle): PoolServer;
export function logServerPoolMarkSuccess(
  pool: LogServerPoolHandle,
  url: string,
  now: bigint,
): void;
export function logServerPoolMarkFailure(
  pool: LogServerPoolHandle,
  url: string,
  now: bigint,
): void;
export function logServerPoolSize(pool: LogServerPoolHandle): number;
export function logServerPoolHealthyCount(pool: LogServerPoolHandle): number;
