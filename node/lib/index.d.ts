/**
 * TypeScript definitions for the nwep N-API addon.
 *
 * nwep is a C library implementing WEB/1 protocol semantics over ngtcp2
 * (QUIC). This module exposes the native bindings to Node.js via N-API.
 */

/// <reference types="node" />

/* ------------------------------------------------------------------ */
/*  Opaque handle types                                               */
/* ------------------------------------------------------------------ */

/** Opaque handle to a native nwep server instance. */
export type ServerHandle = unknown;

/** Opaque handle to a native nwep client instance. */
export type ClientHandle = unknown;

/** Opaque handle to a native nwep connection. */
export type ConnHandle = unknown;

/** Opaque handle to a native nwep stream. */
export type StreamHandle = unknown;

/** Opaque handle to a native nwep handshake state machine. */
export type HandshakeHandle = unknown;

/** Opaque handle to a native nwep anchor set. */
export type AnchorSetHandle = unknown;

/** Opaque handle to a native nwep trust store. */
export type TrustStoreHandle = unknown;

/** Opaque handle to a native nwep identity cache. */
export type IdentityCacheHandle = unknown;

/** Opaque handle to a native nwep log server pool. */
export type LogServerPoolHandle = unknown;

/* ------------------------------------------------------------------ */
/*  Interfaces                                                        */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Constants -- Time                                                 */
/* ------------------------------------------------------------------ */

export const NANOSECONDS: bigint;
export const MICROSECONDS: bigint;
export const MILLISECONDS: bigint;
export const SECONDS: bigint;

/* ------------------------------------------------------------------ */
/*  Constants -- Protocol                                             */
/* ------------------------------------------------------------------ */

export const PROTO_VER: string;
export const ALPN: string;
export const ALPN_LEN: number;
export const DEFAULT_PORT: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Limits                                               */
/* ------------------------------------------------------------------ */

export const DEFAULT_MAX_MESSAGE_SIZE: number;
export const MAX_HEADERS: number;
export const MAX_HEADER_SIZE: number;
export const DEFAULT_MAX_STREAMS: number;
export const DEFAULT_TIMEOUT: bigint;

/* ------------------------------------------------------------------ */
/*  Constants -- Crypto sizes                                         */
/* ------------------------------------------------------------------ */

export const ED25519_PUBKEY_LEN: number;
export const ED25519_PRIVKEY_LEN: number;
export const ED25519_SIG_LEN: number;
export const NODEID_LEN: number;
export const CHALLENGE_LEN: number;
export const REQUEST_ID_LEN: number;
export const TRACE_ID_LEN: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Message types                                        */
/* ------------------------------------------------------------------ */

export const MSG_REQUEST: number;
export const MSG_RESPONSE: number;
export const MSG_STREAM: number;
export const MSG_NOTIFY: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Methods                                              */
/* ------------------------------------------------------------------ */

export const METHOD_READ: string;
export const METHOD_WRITE: string;
export const METHOD_UPDATE: string;
export const METHOD_DELETE: string;
export const METHOD_CONNECT: string;
export const METHOD_AUTHENTICATE: string;
export const METHOD_HEARTBEAT: string;

/* ------------------------------------------------------------------ */
/*  Constants -- Status tokens                                        */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Constants -- Error codes (negative integers)                      */
/* ------------------------------------------------------------------ */

/* Config errors */
export const ERR_CONFIG_FILE_NOT_FOUND: number;
export const ERR_CONFIG_PARSE_ERROR: number;
export const ERR_CONFIG_INVALID_VALUE: number;
export const ERR_CONFIG_MISSING_REQUIRED: number;
export const ERR_CONFIG_VALIDATION_FAILED: number;

/* Network errors */
export const ERR_NETWORK_CONN_FAILED: number;
export const ERR_NETWORK_CONN_CLOSED: number;
export const ERR_NETWORK_TIMEOUT: number;
export const ERR_NETWORK_ADDR_IN_USE: number;
export const ERR_NETWORK_ADDR_INVALID: number;
export const ERR_NETWORK_SOCKET: number;
export const ERR_NETWORK_TLS: number;
export const ERR_NETWORK_QUIC: number;
export const ERR_NETWORK_NO_SERVERS: number;

/* Crypto errors */
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

/* Protocol errors */
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

/* Identity errors */
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

/* Storage errors */
export const ERR_STORAGE_FILE_NOT_FOUND: number;
export const ERR_STORAGE_READ_ERROR: number;
export const ERR_STORAGE_WRITE_ERROR: number;
export const ERR_STORAGE_PERMISSION: number;
export const ERR_STORAGE_DISK_FULL: number;
export const ERR_STORAGE_KEY_NOT_FOUND: number;
export const ERR_STORAGE_INDEX_OUT_OF_RANGE: number;
export const ERR_STORAGE_CORRUPTED: number;

/* Trust errors */
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

/* Internal errors */
export const ERR_INTERNAL_UNKNOWN: number;
export const ERR_INTERNAL_NOT_IMPLEMENTED: number;
export const ERR_INTERNAL_INVALID_STATE: number;
export const ERR_INTERNAL_NULL_PTR: number;
export const ERR_INTERNAL_NOMEM: number;
export const ERR_INTERNAL_INVALID_ARG: number;
export const ERR_INTERNAL_CALLBACK_FAILURE: number;
export const ERR_INTERNAL_NOBUF: number;

/* Error thresholds and limits */
export const ERR_FATAL_THRESHOLD: number;
export const ERR_CONTEXT_MAX: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Frame sizes                                          */
/* ------------------------------------------------------------------ */

export const FRAME_HEADER_SIZE: number;
export const MSG_TYPE_SIZE: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Header names                                         */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Constants -- Base58 / URL                                         */
/* ------------------------------------------------------------------ */

export const BASE58_ADDR_LEN: number;
export const URL_MAX_LEN: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Shamir secret sharing                                */
/* ------------------------------------------------------------------ */

export const SHAMIR_MAX_SHARES: number;
export const SHAMIR_MIN_THRESHOLD: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Key rotation                                         */
/* ------------------------------------------------------------------ */

export const KEY_OVERLAP_SECONDS: number;
export const MAX_ACTIVE_KEYS: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Merkle log                                           */
/* ------------------------------------------------------------------ */

export const LOG_ENTRY_MAX_SIZE: number;
export const MERKLE_PROOF_MAX_DEPTH: number;
export const LOG_ENTRY_KEY_BINDING: number;
export const LOG_ENTRY_KEY_ROTATION: number;
export const LOG_ENTRY_REVOCATION: number;
export const LOG_ENTRY_ANCHOR_CHANGE: number;

/* ------------------------------------------------------------------ */
/*  Constants -- BLS / Anchors                                        */
/* ------------------------------------------------------------------ */

export const BLS_PUBKEY_LEN: number;
export const BLS_PRIVKEY_LEN: number;
export const BLS_SIG_LEN: number;
export const CHECKPOINT_DST: string;
export const DEFAULT_ANCHOR_THRESHOLD: number;
export const MAX_ANCHORS: number;
export const DEFAULT_EPOCH_INTERVAL: bigint;

/* ------------------------------------------------------------------ */
/*  Constants -- Trust                                                */
/* ------------------------------------------------------------------ */

export const STALENESS_WARNING_NS: bigint;
export const STALENESS_REJECT_NS: bigint;
export const IDENTITY_CACHE_TTL: bigint;
export const MAX_CHECKPOINTS: number;
export const STALENESS_FRESH: number;
export const STALENESS_WARNING: number;
export const STALENESS_REJECT: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Roles                                                */
/* ------------------------------------------------------------------ */

export const ROLE_REGULAR: number;
export const ROLE_LOG_SERVER: number;
export const ROLE_ANCHOR: number;
export const ROLE_STR_REGULAR: string;
export const ROLE_STR_LOG_SERVER: string;
export const ROLE_STR_ANCHOR: string;

/* ------------------------------------------------------------------ */
/*  Constants -- Cache / Pool                                         */
/* ------------------------------------------------------------------ */

export const CACHE_DEFAULT_CAPACITY: number;
export const CACHE_DEFAULT_TTL_NS: bigint;
export const POOL_MAX_SERVERS: number;
export const POOL_HEALTH_CHECK_FAILURES: number;
export const POOL_ROUND_ROBIN: number;
export const POOL_RANDOM: number;
export const SERVER_HEALTHY: number;
export const SERVER_UNHEALTHY: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Notify                                               */
/* ------------------------------------------------------------------ */

export const NOTIFY_ID_LEN: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Handshake states                                     */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Constants -- Log levels                                           */
/* ------------------------------------------------------------------ */

export const LOG_TRACE: number;
export const LOG_DEBUG: number;
export const LOG_INFO: number;
export const LOG_WARN: number;
export const LOG_ERROR: number;

/* ------------------------------------------------------------------ */
/*  Constants -- Error categories                                     */
/* ------------------------------------------------------------------ */

export const ERR_CAT_NONE: number;
export const ERR_CAT_CONFIG: number;
export const ERR_CAT_NETWORK: number;
export const ERR_CAT_CRYPTO: number;
export const ERR_CAT_PROTOCOL: number;
export const ERR_CAT_IDENTITY: number;
export const ERR_CAT_STORAGE: number;
export const ERR_CAT_TRUST: number;
export const ERR_CAT_INTERNAL: number;

/* ------------------------------------------------------------------ */
/*  Core                                                              */
/* ------------------------------------------------------------------ */

/** Initialize the nwep library. Must be called before any other function. */
export function init(): void;

/** Return the nwep library version string. */
export function version(): string;

/* ------------------------------------------------------------------ */
/*  Error functions                                                   */
/* ------------------------------------------------------------------ */

/** Return a human-readable string for an error code. */
export function strerror(code: number): string;

/** Return whether an error code represents a fatal error. */
export function errIsFatal(code: number): boolean;

/** Return the error category for an error code. */
export function errCategory(code: number): number;

/** Return a human-readable string for an error category. */
export function errCategoryStr(category: number): string;

/** Map an error code to its corresponding status token string. */
export function errToStatus(code: number): string;

/** Format an error with optional context strings into a descriptive message. */
export function errorFormat(input: ErrorFormatInput): string;

/* ------------------------------------------------------------------ */
/*  Crypto functions                                                  */
/* ------------------------------------------------------------------ */

/** Generate a new Ed25519 keypair. */
export function keypairGenerate(): Keypair;

/** Derive an Ed25519 keypair from a 32-byte seed. */
export function keypairFromSeed(seed: Buffer): Keypair;

/** Reconstruct an Ed25519 keypair from a 64-byte private key. */
export function keypairFromPrivkey(privkey: Buffer): Keypair;

/** Derive a NodeID from a 32-byte Ed25519 public key. */
export function nodeidFromPubkey(pubkey: Buffer): Buffer;

/** Derive a NodeID from a keypair. */
export function nodeidFromKeypair(keypair: Keypair): Buffer;

/** Check whether two NodeIDs are equal. */
export function nodeidEq(a: Buffer, b: Buffer): boolean;

/** Check whether a NodeID is all zeros. */
export function nodeidIsZero(nodeid: Buffer): boolean;

/** Sign a message with a keypair, returning a 64-byte signature. */
export function sign(message: Buffer, keypair: Keypair): Buffer;

/** Verify a signature against a message and public key. */
export function verify(
  signature: Buffer,
  message: Buffer,
  pubkey: Buffer,
): boolean;

/** Generate a 32-byte random challenge. */
export function challengeGenerate(): Buffer;

/** Sign a challenge with a keypair, returning a 64-byte response. */
export function challengeSign(challenge: Buffer, keypair: Keypair): Buffer;

/** Verify a challenge response against the original challenge and public key. */
export function challengeVerify(
  response: Buffer,
  challenge: Buffer,
  pubkey: Buffer,
): boolean;

/** Generate cryptographically secure random bytes. */
export function randomBytes(length: number): Buffer;

/** Split a 32-byte secret into n Shamir shares with threshold t. */
export function shamirSplit(
  secret: Buffer,
  numShares: number,
  threshold: number,
): ShamirShare[];

/** Combine Shamir shares to reconstruct the original 32-byte secret. */
export function shamirCombine(shares: ShamirShare[]): Buffer;

/** Generate a random 16-byte trace ID. */
export function traceIdGenerate(): Buffer;

/** Generate a random 16-byte request ID. */
export function requestIdGenerate(): Buffer;

/* ------------------------------------------------------------------ */
/*  Encoding functions                                                */
/* ------------------------------------------------------------------ */

/** Encode binary data as a Base58 string. */
export function base58Encode(data: Buffer): string;

/** Decode a Base58 string to binary data. */
export function base58Decode(encoded: string): Buffer;

/** Encode binary data as a Base64 string. */
export function base64Encode(data: Buffer): string;

/** Decode a Base64 string to binary data. */
export function base64Decode(encoded: string): Buffer;

/** Encode a uint32 as a 4-byte big-endian buffer. */
export function putUint32be(value: number): Buffer;

/** Decode a uint32 from a big-endian buffer (at least 4 bytes). */
export function getUint32be(data: Buffer): number;

/** Encode a uint16 as a 2-byte big-endian buffer. */
export function putUint16be(value: number): Buffer;

/** Decode a uint16 from a big-endian buffer (at least 2 bytes). */
export function getUint16be(data: Buffer): number;

/* ------------------------------------------------------------------ */
/*  Address functions                                                 */
/* ------------------------------------------------------------------ */

/** Encode an address to its Base58 string representation. */
export function addrEncode(addr: NwepAddr): string;

/** Decode a Base58 address string into an NwepAddr. */
export function addrDecode(encoded: string): NwepAddr;

/** Parse a `web://` URL string into an NwepUrl. */
export function urlParse(url: string): NwepUrl;

/** Format an NwepUrl into a `web://` URL string. */
export function urlFormat(url: NwepUrl): string;

/** Set the IPv4 address on an NwepAddr (as a uint32), returning a new addr. */
export function addrSetIpv4(addr: NwepAddr, ipv4: number): NwepAddr;

/** Set the IPv6 address on an NwepAddr (as a 16-byte buffer), returning a new addr. */
export function addrSetIpv6(addr: NwepAddr, ipv6: Buffer): NwepAddr;

/* ------------------------------------------------------------------ */
/*  Message functions                                                 */
/* ------------------------------------------------------------------ */

/** Encode a message to its wire-format buffer. */
export function msgEncode(msg: NwepMsg): Buffer;

/** Decode a wire-format buffer into a message. */
export function msgDecode(data: Buffer): NwepMsg;

/** Decode only the frame header, returning the payload length. */
export function msgDecodeHeader(data: Buffer): number;

/** Compute the encoded length of a message. */
export function msgEncodeLen(msg: NwepMsg): number;

/** Build and encode a request message. */
export function requestBuild(
  method: string,
  path: string,
  body?: Buffer | null,
  headers?: MsgHeader[],
): Buffer;

/** Build and encode a response message. */
export function responseBuild(
  status: string,
  details?: string | null,
  body?: Buffer | null,
  headers?: MsgHeader[],
): Buffer;

/** Check whether a method string is valid. */
export function methodIsValid(method: string): boolean;

/** Check whether a method is idempotent. */
export function methodIsIdempotent(method: string): boolean;

/** Check whether a method is allowed in 0-RTT. */
export function methodAllowed0rtt(method: string): boolean;

/** Check whether a status token string is valid. */
export function statusIsValid(status: string): boolean;

/** Check whether a status token indicates success. */
export function statusIsSuccess(status: string): boolean;

/** Check whether a status token indicates an error. */
export function statusIsError(status: string): boolean;

/* ------------------------------------------------------------------ */
/*  Handshake functions                                               */
/* ------------------------------------------------------------------ */

/** Initialize a client-side handshake state machine. */
export function handshakeClientInit(
  keypair: Keypair,
  expectedNodeid?: Buffer | null,
): HandshakeHandle;

/** Initialize a server-side handshake state machine. */
export function handshakeServerInit(keypair: Keypair): HandshakeHandle;

/** Explicitly free a handshake handle. */
export function handshakeFree(handle: HandshakeHandle): void;

/** Set negotiation parameters on a handshake. */
export function handshakeSetParams(
  handle: HandshakeHandle,
  params: HandshakeParams,
): void;

/** Return a human-readable string for a client handshake state. */
export function clientStateStr(state: number): string;

/** Return a human-readable string for a server handshake state. */
export function serverStateStr(state: number): string;

/* ------------------------------------------------------------------ */
/*  Log functions                                                     */
/* ------------------------------------------------------------------ */

/** Return a human-readable string for a log level. */
export function logLevelStr(level: number): string;

/** Set the global log level. */
export function logSetLevel(level: number): void;

/** Get the current global log level. */
export function logGetLevel(): number;

/** Enable or disable JSON-formatted log output. */
export function logSetJson(enabled: boolean): void;

/** Enable or disable logging to stderr. */
export function logSetStderr(enabled: boolean): void;

/** Write a log message at the given level. */
export function logWrite(
  level: number,
  component: string,
  message: string,
): void;

/** Format a log entry as a JSON string. */
export function logFormatJson(entry: LogEntry): string;

/* ------------------------------------------------------------------ */
/*  Identity management functions                                     */
/* ------------------------------------------------------------------ */

/** Create a new recovery authority with a freshly generated keypair. */
export function recoveryAuthorityNew(): RecoveryAuthority;

/** Get the public key from a recovery authority. */
export function recoveryAuthorityGetPubkey(
  authority: RecoveryAuthority,
): Buffer | null;

/** Create a new managed identity from a keypair and timestamp. */
export function managedIdentityNew(
  keypair: Keypair,
  now: bigint,
  recoveryAuthority?: RecoveryAuthority | null,
): ManagedIdentity;

/** Rotate keys on a managed identity (currently throws; use C-level API). */
export function managedIdentityRotate(): never;

/** Check whether a managed identity has been revoked. */
export function managedIdentityIsRevoked(identity: ManagedIdentity): boolean;

/* ------------------------------------------------------------------ */
/*  Server functions                                                  */
/* ------------------------------------------------------------------ */

/** Create a new server instance. Returns the server handle and its keypair. */
export function serverNew(settings?: ServerSettings): ServerNewResult;

/** Explicitly free a server instance. */
export function serverFree(server: ServerHandle): void;

/** Feed a received packet to the server. */
export function serverRead(
  server: ServerHandle,
  path: Buffer,
  data: Buffer,
  timestamp: bigint,
): void;

/** Get the next packet to send from the server, or null if none available. */
export function serverWrite(
  server: ServerHandle,
  timestamp: bigint,
): ServerWriteResult | null;

/** Notify the server that a timer has expired. */
export function serverHandleExpiry(
  server: ServerHandle,
  timestamp: bigint,
): void;

/** Get the next expiry deadline for the server. */
export function serverGetExpiry(server: ServerHandle): bigint;

/** Gracefully close the server. */
export function serverClose(server: ServerHandle): void;

/* ------------------------------------------------------------------ */
/*  Client functions                                                  */
/* ------------------------------------------------------------------ */

/** Create a new client instance. Returns the client handle and its keypair. */
export function clientNew(settings?: ClientSettings): ClientNewResult;

/** Explicitly free a client instance. */
export function clientFree(client: ClientHandle): void;

/** Initiate a connection to the given URL. */
export function clientConnect(
  client: ClientHandle,
  url: string,
  timestamp: bigint,
): void;

/** Feed a received packet to the client. */
export function clientRead(
  client: ClientHandle,
  data: Buffer,
  timestamp: bigint,
): void;

/** Get the next packet to send from the client, or null if none available. */
export function clientWrite(
  client: ClientHandle,
  timestamp: bigint,
): Buffer | null;

/** Notify the client that a timer has expired. */
export function clientHandleExpiry(
  client: ClientHandle,
  timestamp: bigint,
): void;

/** Get the next expiry deadline for the client. */
export function clientGetExpiry(client: ClientHandle): bigint;

/** Gracefully close the client. */
export function clientClose(client: ClientHandle): void;

/** Get the connection handle from a connected client. */
export function clientGetConn(client: ClientHandle): ConnHandle | null;

/* ------------------------------------------------------------------ */
/*  Connection functions                                              */
/* ------------------------------------------------------------------ */

/** Get the peer's verified identity from a connection. */
export function connGetPeerIdentity(conn: ConnHandle): Identity;

/** Get the local identity from a connection. */
export function connGetLocalIdentity(conn: ConnHandle): Identity;

/** Get the local role string from a connection. */
export function connGetRole(conn: ConnHandle): string | null;

/** Close a connection with an error code. */
export function connClose(conn: ConnHandle, errorCode: number): void;


/* ------------------------------------------------------------------ */
/*  Stream functions                                                  */
/* ------------------------------------------------------------------ */

/** Send a response on a stream. */
export function streamRespond(
  stream: StreamHandle,
  response: NwepResponse,
): void;

/** Write data to a stream, returning the number of bytes written. */
export function streamWrite(stream: StreamHandle, data: Buffer): number;

/** Signal end-of-stream. */
export function streamEnd(stream: StreamHandle): void;

/** Close a stream with an error code. */
export function streamClose(stream: StreamHandle, errorCode: number): void;

/** Get the stream ID. */
export function streamGetId(stream: StreamHandle): number;

/** Check whether a stream was initiated by the server. */
export function streamIsServerInitiated(stream: StreamHandle): boolean;

/** Get the connection handle that owns this stream. */
export function streamGetConn(stream: StreamHandle): ConnHandle | null;

/* ------------------------------------------------------------------ */
/*  Merkle tree functions                                             */
/* ------------------------------------------------------------------ */

/** Encode a Merkle log entry to its wire format. */
export function merkleEntryEncode(entry: MerkleEntry): Buffer;

/** Decode a Merkle log entry from wire-format data. */
export function merkleEntryDecode(data: Buffer): MerkleEntry;

/** Compute the leaf hash for a Merkle log entry. */
export function merkleLeafHash(entry: MerkleEntry): Buffer;

/** Compute the internal node hash from two child hashes. */
export function merkleNodeHash(left: Buffer, right: Buffer): Buffer;

/** Verify a Merkle inclusion proof against a root hash. */
export function merkleProofVerify(proof: MerkleProof, root: Buffer): boolean;

/** Encode a Merkle proof to its wire format. */
export function merkleProofEncode(proof: MerkleProof): Buffer;

/** Decode a Merkle proof from wire-format data. */
export function merkleProofDecode(data: Buffer): MerkleProof;

/* ------------------------------------------------------------------ */
/*  BLS / Anchor functions                                            */
/* ------------------------------------------------------------------ */

/** Generate a new BLS keypair. */
export function blsKeypairGenerate(): BlsKeypair;

/** Derive a BLS keypair from a seed buffer. */
export function blsKeypairFromSeed(seed: Buffer): BlsKeypair;

/** Sign a message with a BLS keypair, returning a 96-byte signature. */
export function blsSign(keypair: BlsKeypair, message: Buffer): Buffer;

/** Verify a BLS signature against a public key and message. */
export function blsVerify(
  pubkey: Buffer,
  signature: Buffer,
  message: Buffer,
): boolean;

/** Aggregate multiple BLS signatures into a single signature. */
export function blsAggregateSigs(signatures: Buffer[]): Buffer;

/** Verify an aggregated BLS signature against multiple public keys. */
export function blsVerifyAggregate(
  pubkeys: Buffer[],
  signature: Buffer,
  message: Buffer,
): boolean;

/** Create a new anchor set with the given quorum threshold. */
export function anchorSetNew(threshold: number): AnchorSetHandle;

/** Explicitly free an anchor set (also freed on GC). */
export function anchorSetFree(set: AnchorSetHandle): void;

/** Add an anchor public key to the set. */
export function anchorSetAdd(
  set: AnchorSetHandle,
  pubkey: Buffer,
  builtin: boolean,
): void;

/** Remove an anchor public key from the set. */
export function anchorSetRemove(
  set: AnchorSetHandle,
  pubkey: Buffer,
): void;

/** Get the number of anchors in the set. */
export function anchorSetSize(set: AnchorSetHandle): number;

/** Get the quorum threshold of the anchor set. */
export function anchorSetThreshold(set: AnchorSetHandle): number;

/** Check whether a public key is in the anchor set. */
export function anchorSetContains(
  set: AnchorSetHandle,
  pubkey: Buffer,
): boolean;

/** Create a new checkpoint. */
export function checkpointNew(
  epoch: bigint,
  timestamp: bigint,
  merkleRoot: Buffer,
  logSize: bigint,
): Checkpoint;

/** Encode a checkpoint to its wire format. */
export function checkpointEncode(checkpoint: Checkpoint): Buffer;

/** Decode a checkpoint from wire-format data. */
export function checkpointDecode(data: Buffer): Checkpoint;

/* ------------------------------------------------------------------ */
/*  Trust store functions                                             */
/* ------------------------------------------------------------------ */

/** Return default trust settings. */
export function trustSettingsDefault(): TrustSettings;

/** Create a new trust store, optionally with custom settings. */
export function trustStoreNew(settings?: TrustSettings): TrustStoreHandle;

/** Explicitly free a trust store (also freed on GC). */
export function trustStoreFree(store: TrustStoreHandle): void;

/** Add a trust anchor to the store. */
export function trustStoreAddAnchor(
  store: TrustStoreHandle,
  pubkey: Buffer,
  builtin: boolean,
): void;

/** Remove a trust anchor from the store. */
export function trustStoreRemoveAnchor(
  store: TrustStoreHandle,
  pubkey: Buffer,
): void;

/** Add a checkpoint to the trust store. */
export function trustStoreAddCheckpoint(
  store: TrustStoreHandle,
  checkpoint: Checkpoint,
): void;

/** Get the latest checkpoint from the store, or null if none. */
export function trustStoreGetLatestCheckpoint(
  store: TrustStoreHandle,
): Checkpoint | null;

/** Get the number of checkpoints in the store. */
export function trustStoreCheckpointCount(store: TrustStoreHandle): number;

/** Check the staleness level of the trust store given the current time. */
export function trustStoreCheckStaleness(
  store: TrustStoreHandle,
  now: bigint,
): number;

/** Get the staleness age of the trust store in nanoseconds. */
export function trustStoreGetStalenessAge(
  store: TrustStoreHandle,
  now: bigint,
): bigint;

/* ------------------------------------------------------------------ */
/*  Role functions                                                    */
/* ------------------------------------------------------------------ */

/** Convert a role string to its numeric enum value. */
export function roleFromStr(role: string): number;

/** Convert a numeric role enum value to its string representation. */
export function roleToStr(role: number): string;

/* ------------------------------------------------------------------ */
/*  Identity cache functions                                          */
/* ------------------------------------------------------------------ */

/** Create a new identity cache, optionally with custom settings. */
export function identityCacheNew(
  settings?: IdentityCacheSettings,
): IdentityCacheHandle;

/** Explicitly free an identity cache (also freed on GC). */
export function identityCacheFree(cache: IdentityCacheHandle): void;

/** Look up a cached identity by NodeID. Returns null if not found or expired. */
export function identityCacheLookup(
  cache: IdentityCacheHandle,
  nodeid: Buffer,
  now: bigint,
): CachedIdentity | null;

/** Store an identity in the cache. */
export function identityCacheStore(
  cache: IdentityCacheHandle,
  nodeid: Buffer,
  pubkey: Buffer,
  logIndex: bigint,
  now: bigint,
): void;

/** Invalidate a cached identity by NodeID. */
export function identityCacheInvalidate(
  cache: IdentityCacheHandle,
  nodeid: Buffer,
): void;

/** Remove all entries from the identity cache. */
export function identityCacheClear(cache: IdentityCacheHandle): void;

/** Get the current number of entries in the identity cache. */
export function identityCacheSize(cache: IdentityCacheHandle): number;

/** Get the maximum capacity of the identity cache. */
export function identityCacheCapacity(cache: IdentityCacheHandle): number;

/* ------------------------------------------------------------------ */
/*  Log server pool functions                                         */
/* ------------------------------------------------------------------ */

/** Create a new log server pool, optionally with custom settings. */
export function logServerPoolNew(
  settings?: unknown,
): LogServerPoolHandle;

/** Explicitly free a log server pool (also freed on GC). */
export function logServerPoolFree(pool: LogServerPoolHandle): void;

/** Add a server URL to the pool. */
export function logServerPoolAdd(
  pool: LogServerPoolHandle,
  url: string,
): void;

/** Remove a server URL from the pool. */
export function logServerPoolRemove(
  pool: LogServerPoolHandle,
  url: string,
): void;

/** Select a healthy server from the pool. */
export function logServerPoolSelect(pool: LogServerPoolHandle): PoolServer;

/** Mark a server as having succeeded at the given timestamp. */
export function logServerPoolMarkSuccess(
  pool: LogServerPoolHandle,
  url: string,
  now: bigint,
): void;

/** Mark a server as having failed at the given timestamp. */
export function logServerPoolMarkFailure(
  pool: LogServerPoolHandle,
  url: string,
  now: bigint,
): void;

/** Get the total number of servers in the pool. */
export function logServerPoolSize(pool: LogServerPoolHandle): number;

/** Get the number of healthy servers in the pool. */
export function logServerPoolHealthyCount(pool: LogServerPoolHandle): number;
