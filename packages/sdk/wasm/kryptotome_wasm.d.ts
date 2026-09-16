/* tslint:disable */
/* eslint-disable */

export class WasmSessionManager {
    free(): void;
    [Symbol.dispose](): void;
    hostPublicKeyHex(): string;
    /**
     * Issues ephemeral session token for a table peer
     */
    issuePeerAttestation(recipient_peer_id: string, package_id: string, content_digest: string, scopes_json: string, duration_minutes: number): string;
    constructor(session_id: string);
    /**
     * Peer validates received session token
     */
    static verifyPeerAttestation(attestation_json: string, host_pubkey_hex: string): boolean;
}

export class WasmVerifier {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Exits the current active game session and purges all unlocked compendiums
     */
    exitSession(): number;
    /**
     * Invalidates entitlement if the current content digest has changed
     */
    invalidateIfDigestMismatch(package_id: string, current_digest: string): boolean;
    /**
     * Invalidates entitlement for a specific package
     */
    invalidatePackage(package_id: string): boolean;
    /**
     * Checks if a package is currently unlocked in the local session cache
     */
    isPackageUnlocked(package_id: string): boolean;
    constructor();
    /**
     * Prunes expired entitlements from the cache
     */
    pruneExpired(): number;
    /**
     * Invalidates entitlement when package assets are reloaded
     */
    reloadPackage(package_id: string): boolean;
    /**
     * Configures the default cache TTL duration in seconds
     */
    setCacheTtlSeconds(seconds: bigint): void;
    /**
     * Verifies a self-contained EntitlementProofBundle JSON string against a challenge JSON string
     */
    verifyProofBundle(bundle_json: string, challenge_json: string): boolean;
    /**
     * Verifies a ZK proof against publisher key and challenge nonce JSON
     */
    verifyZkProof(publisher_vk_hex: string, challenge_json: string, proof_json: string): boolean;
}

export function main_js(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmsessionmanager_free: (a: number, b: number) => void;
    readonly __wbg_wasmverifier_free: (a: number, b: number) => void;
    readonly main_js: () => void;
    readonly wasmsessionmanager_hostPublicKeyHex: (a: number, b: number) => void;
    readonly wasmsessionmanager_issuePeerAttestation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
    readonly wasmsessionmanager_new: (a: number, b: number) => number;
    readonly wasmsessionmanager_verifyPeerAttestation: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly wasmverifier_exitSession: (a: number) => number;
    readonly wasmverifier_invalidateIfDigestMismatch: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly wasmverifier_invalidatePackage: (a: number, b: number, c: number) => number;
    readonly wasmverifier_isPackageUnlocked: (a: number, b: number, c: number) => number;
    readonly wasmverifier_new: () => number;
    readonly wasmverifier_pruneExpired: (a: number) => number;
    readonly wasmverifier_reloadPackage: (a: number, b: number, c: number) => number;
    readonly wasmverifier_setCacheTtlSeconds: (a: number, b: bigint) => void;
    readonly wasmverifier_verifyProofBundle: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly wasmverifier_verifyZkProof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_export2: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export3: (a: number, b: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
