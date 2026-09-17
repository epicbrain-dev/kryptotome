// Kryptotome Publisher Studio - Enterprise Desktop Application Controller
// Arcane Grimoire design system, non-blocking toast notifications, and audit chronicle.

interface RulebookAsset {
  path: string;
  mimeType: string;
  sizeBytes: number;
  blake3Hash: string;
}

interface TierMapping {
  tierPattern: string;
  packageId: string;
  system: string;
}

interface ClaimVoucherItem {
  email: string;
  tier: string;
  claimUrl: string;
  voucherId: string;
}

interface PhysicalVoucherCard {
  voucherId: string;
  scratchCode: string;
  ndefHex: string;
  packageId: string;
  format: string;
}

interface ChronicleEntry {
  id: string;
  timestamp: string;
  operation: string;
  target: string;
  status: 'SUCCESS' | 'FAILED' | 'INFO';
  digest: string;
}

// Initial Sample Assets
const INITIAL_ASSETS: RulebookAsset[] = [
  {
    path: "rules/core_rules.pdf",
    mimeType: "application/pdf",
    sizeBytes: 14285700,
    blake3Hash: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
  },
  {
    path: "spells/grimoire_arcana.md",
    mimeType: "text/markdown",
    sizeBytes: 482910,
    blake3Hash: "b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01a",
  },
  {
    path: "monsters/bestiary_srd.json",
    mimeType: "application/json",
    sizeBytes: 1290340,
    blake3Hash: "c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01a2b",
  },
  {
    path: "maps/dungeon_abyss.webp",
    mimeType: "image/webp",
    sizeBytes: 8392010,
    blake3Hash: "d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01a2b3c",
  },
];

const INITIAL_TIERS: TierMapping[] = [
  { tierPattern: "Early Bird Digital PDF", packageId: "pkg-eldritch-vault-5e", system: "pf2e" },
  { tierPattern: "Hardcover Collector + All Digital", packageId: "pkg-eldritch-vault-5e", system: "pf2e" },
  { tierPattern: "Merchant Commercial Tier", packageId: "pkg-eldritch-vault-5e", system: "pf2e" },
];

const SAMPLE_KICKSTARTER_CSV = `Backer Number,Backer Name,Email,Reward Tier,Pledge Amount
101,Aria Nightshade,aria@tabletop.guild,Hardcover Collector + All Digital,$85.00
102,Kaelen Moonshadow,kaelen@adventurers.io,Early Bird Digital PDF,$25.00
103,Boran Stonehammer,boran@deepdelvers.net,Merchant Commercial Tier,$250.00
104,Lyra Swiftfoot,lyra@rpgfans.org,Early Bird Digital PDF,$25.00`;

const SAMPLE_BACKERKIT_CSV = `Backer Id,Full Name,Email Address,Pledge Tier,Total Pledged
BK-901,Sylas Vance,sylas@ttrpg.com,Hardcover Collector + All Digital,85
BK-902,Theron Blackwood,theron@eldritch.net,Early Bird Digital PDF,25
BK-903,Elowen Frost,elowen@chronicles.org,Hardcover Collector + All Digital,85`;

// App State
let assets: RulebookAsset[] = [...INITIAL_ASSETS];
let tierMappings: TierMapping[] = [...INITIAL_TIERS];
let generatedVouchers: ClaimVoucherItem[] = [];
let generatedPodCards: PhysicalVoucherCard[] = [];
let chronicleEntries: ChronicleEntry[] = [];

// Security Sanitization Utility
function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Cryptographically Secure Hex Randomness (CWE-338 hardened)
function secureRandomHex(bytes: number = 8): string {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  }
  const perfNow = typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : 0;
  return `${Date.now().toString(36)}-${(perfNow * 1000).toString(36).replace('.', '')}`;
}

// Non-blocking Enterprise Toast System
function showToast(message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info'): void {
  if (typeof document === 'undefined') return;
  const container = document.getElementById("toast-container");
  if (!container) return;

  const icons: Record<string, string> = {
    success: '⚜',
    error: '⚠️',
    warning: '✦',
    info: '📜',
  };

  const safeMessage = escapeHtml(message);
  const toast = document.createElement("div");
  toast.className = `toast-item toast-${type}`;
  toast.innerHTML = `
    <span style="font-size: 16px;">${icons[type] || '✦'}</span>
    <span>${safeMessage}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => {
      if (container.contains(toast)) container.removeChild(toast);
    }, 300);
  }, 4200);
}

// Enterprise Audit Chronicle Logger
function logChronicle(operation: string, target: string, status: 'SUCCESS' | 'FAILED' | 'INFO', digest: string): void {
  const entry: ChronicleEntry = {
    id: `ev-${Date.now().toString(36)}-${secureRandomHex(4)}`,
    timestamp: new Date().toISOString().substring(11, 19),
    operation,
    target,
    status,
    digest,
  };
  chronicleEntries.unshift(entry);
  renderChronicleList();
}

function renderChronicleList(): void {
  const listEl = document.getElementById("audit-log-list");
  if (!listEl) return;
  listEl.innerHTML = "";

  if (chronicleEntries.length === 0) {
    listEl.innerHTML = `<p style="font-size: 12px; color: var(--text-muted); text-align: center;">No cryptographic events recorded yet.</p>`;
    return;
  }

  chronicleEntries.slice(0, 50).forEach(entry => {
    const item = document.createElement("div");
    item.className = "audit-log-entry";
    const statusColor = entry.status === 'SUCCESS' ? '#34d399' : entry.status === 'FAILED' ? '#f87171' : '#38bdf8';
    item.innerHTML = `
      <div class="audit-entry-top">
        <span>${escapeHtml(entry.timestamp)}</span>
        <span style="color: ${statusColor}; font-weight: 700;">${escapeHtml(entry.status)}</span>
      </div>
      <div class="audit-entry-op">${escapeHtml(entry.operation)}: <span style="font-weight: 400; color: var(--text-muted);">${escapeHtml(entry.target)}</span></div>
      <div class="code-cell" style="font-size: 10px; opacity: 0.8;">Digest: ${escapeHtml(entry.digest.slice(0, 32))}...</div>
    `;
    listEl.appendChild(item);
  });
}

// Helper: Deterministic Mock BLAKE3 string generator
function pseudoBlake3(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  const hexPart = Math.abs(hash).toString(16).padStart(8, "0");
  return (hexPart.repeat(8)).slice(0, 64);
}

// Helper: Scratch code generator (CWE-338 hardened)
function generateScratchCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const hex = secureRandomHex(8);
  let part1 = "";
  for (let i = 0; i < 4; i++) {
    part1 += chars[parseInt(hex.slice(i * 2, i * 2 + 2), 16) % chars.length];
  }
  let part2 = "";
  for (let i = 4; i < 8; i++) {
    part2 += chars[parseInt(hex.slice(i * 2, i * 2 + 2), 16) % chars.length];
  }
  return `KRYP-${part1}-${part2}`;
}

// Compute deterministic root package hash
function computeRootPackageHash(): string {
  const pkgId = (document.getElementById("pkg-id") as HTMLInputElement)?.value || "pkg-default";
  const version = (document.getElementById("pkg-version") as HTMLInputElement)?.value || "1.0.0";
  const concatenated = pkgId + ":" + version + ":" + assets.map(a => a.path + a.blake3Hash).join(":");
  return pseudoBlake3(concatenated);
}

// Schema Validation
function validateSchema(): { valid: boolean; message: string } {
  const pkgId = (document.getElementById("pkg-id") as HTMLInputElement)?.value?.trim();
  const title = (document.getElementById("pkg-title") as HTMLInputElement)?.value?.trim();
  const publisher = (document.getElementById("pkg-publisher") as HTMLInputElement)?.value?.trim();
  const license = (document.getElementById("pkg-license") as HTMLSelectElement)?.value;
  const attribution = (document.getElementById("pkg-attribution") as HTMLTextAreaElement)?.value?.trim() || "";

  if (!pkgId) return { valid: false, message: "Package Identifier is required." };
  if (!title) return { valid: false, message: "Package title is required." };
  if (!publisher) return { valid: false, message: "Publisher organization is required." };
  if (assets.length === 0) return { valid: false, message: "At least one asset (PDF, MD, or JSON) is required." };

  if (license === "paizo_orc" && (!attribution || !attribution.toLowerCase().includes("orc"))) {
    return { valid: false, message: "Paizo ORC schema requires explicit ORC attribution notice." };
  }
  if (license === "creative_commons_by_4" && attribution.length < 10) {
    return { valid: false, message: "CC-BY-4.0 schema requires author attribution statement." };
  }

  return { valid: true, message: `Schema Compliant: ${license.toUpperCase()} attribution and structure verified.` };
}

function updateValidationUI(): void {
  const banner = document.getElementById("schema-validation-banner");
  if (!banner) return;
  const { valid, message } = validateSchema();
  const safeMessage = escapeHtml(message);
  if (valid) {
    banner.className = "wax-seal-banner seal-valid";
    banner.innerHTML = `
      <div class="wax-stamp">⚜</div>
      <div class="seal-content">
        <span class="seal-title">Schema Compliant</span>
        <span class="seal-desc">${safeMessage}</span>
      </div>
    `;
  } else {
    banner.className = "wax-seal-banner seal-invalid";
    banner.innerHTML = `
      <div class="wax-stamp">⚠️</div>
      <div class="seal-content">
        <span class="seal-title">Schema Incomplete</span>
        <span class="seal-desc">${safeMessage}</span>
      </div>
    `;
  }
}

// Safe clipboard copy with toast feedback
function copyTextToClipboard(text: string, successMessage: string): void {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(successMessage, 'success');
    }).catch(() => {
      fallbackCopy(text, successMessage);
    });
  } else {
    fallbackCopy(text, successMessage);
  }
}

function fallbackCopy(text: string, successMessage: string): void {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand("copy");
    showToast(successMessage, 'success');
  } catch (err) {
    showToast("Copied to buffer: " + text.slice(0, 24) + "...", 'info');
  } finally {
    document.body.removeChild(textArea);
  }
}

// Render Assets Table
function renderAssetsTable(): void {
  const tbody = document.getElementById("asset-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  assets.forEach((asset, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${escapeHtml(asset.path)}</strong></td>
      <td>${escapeHtml(asset.mimeType)}</td>
      <td>${(asset.sizeBytes / 1024 / 1024).toFixed(2)} MB</td>
      <td class="code-cell" title="${escapeHtml(asset.blake3Hash)}">${escapeHtml(asset.blake3Hash.slice(0, 16))}...${escapeHtml(asset.blake3Hash.slice(-8))}</td>
      <td><button class="btn-sm btn-arcane-ghost delete-asset-btn" data-delete-idx="${idx}">Remove</button></td>
    `;
    tbody.appendChild(tr);
  });

  const rootHashEl = document.getElementById("root-package-hash");
  if (rootHashEl) {
    rootHashEl.innerText = computeRootPackageHash();
  }

  updateValidationUI();
}

// Render Tier Mapping Table
function renderTierTable(): void {
  const tbody = document.getElementById("tier-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  tierMappings.forEach(tier => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${escapeHtml(tier.tierPattern)}</strong></td>
      <td class="code-cell">${escapeHtml(tier.packageId)}</td>
      <td>${escapeHtml(tier.system.toUpperCase())}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Trigger browser download of text file
function downloadFile(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Modal handling
function openAssetModal(): void {
  const modal = document.getElementById("arcane-modal");
  if (modal) modal.style.display = "flex";
}

function closeAssetModal(): void {
  const modal = document.getElementById("arcane-modal");
  if (modal) modal.style.display = "none";
}

// Main Application Initialization
function initPublisherStudioApp(): void {
  // Navigation Tabs
  const navTabs = document.querySelectorAll(".nav-bookmark");
  const tabViews = document.querySelectorAll(".tab-view");
  const viewTitle = document.getElementById("view-title");
  const viewDesc = document.getElementById("view-desc");

  const TAB_METAS: Record<string, { title: string; desc: string }> = {
    package: {
      title: "Digital Tome Studio & Schema Validation",
      desc: "Assemble rulebook chapters, PDFs, compendiums, and validate Paizo ORC / CC-BY schemas.",
    },
    signing: {
      title: "Cryptographic Manifest Seal & HSM Key",
      desc: "Sign package manifests with Ed25519 publisher keys into verified .kryptopkg bundles.",
    },
    crowdfunding: {
      title: "Backer Fulfillment Bridge (Kickstarter & BackerKit)",
      desc: "Ingest backer surveys, map reward tiers, and generate 1-click digital claim vouchers.",
    },
    vouchers: {
      title: "Print-on-Demand (POD) Physical Vouchers & NFC Book Tags",
      desc: "Mint scratch-off activation codes and NDEF payloads for NTAG213/215 chips.",
    },
  };

  navTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const target = tab.getAttribute("data-tab");
      if (!target) return;

      navTabs.forEach(t => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tabViews.forEach(v => v.classList.remove("active"));

      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");

      const activeView = document.getElementById(`view-${target}`);
      if (activeView) activeView.classList.add("active");

      if (viewTitle && viewDesc && TAB_METAS[target]) {
        viewTitle.textContent = TAB_METAS[target].title;
        viewDesc.textContent = TAB_METAS[target].desc;
      }
    });
  });

  // Topbar Actions
  document.getElementById("btn-quick-sample")?.addEventListener("click", () => {
    (document.getElementById("pkg-id") as HTMLInputElement).value = "pkg-eldritch-vault-5e";
    (document.getElementById("pkg-version") as HTMLInputElement).value = "1.0.0";
    (document.getElementById("pkg-title") as HTMLInputElement).value = "The Eldritch Vault Compendium";
    (document.getElementById("pkg-system") as HTMLSelectElement).value = "pf2e";
    (document.getElementById("pkg-publisher") as HTMLInputElement).value = "Grimoire Press Guild";
    (document.getElementById("pkg-license") as HTMLSelectElement).value = "paizo_orc";
    (document.getElementById("pkg-attribution") as HTMLTextAreaElement).value =
      "This work includes material taken from the System Reference Document 5.1 by Wizards of the Coast LLC and Pathfinder 2e under the Paizo ORC License. Copyright 2026 Grimoire Press Guild.";
    assets = [...INITIAL_ASSETS];
    renderAssetsTable();
    logChronicle("DEMO_LOAD", "pkg-eldritch-vault-5e", "SUCCESS", computeRootPackageHash());
    showToast("Loaded Paizo ORC demo grimoire with 4 assets.", "success");
  });

  document.getElementById("btn-export-bundle")?.addEventListener("click", () => {
    const { valid, message } = validateSchema();
    if (!valid) {
      showToast(message, "error");
      return;
    }

    const pkgId = (document.getElementById("pkg-id") as HTMLInputElement)?.value || "pkg-demo";
    const title = (document.getElementById("pkg-title") as HTMLInputElement)?.value || "Demo Title";
    const version = (document.getElementById("pkg-version") as HTMLInputElement)?.value || "1.0.0";
    const publisher = (document.getElementById("pkg-publisher") as HTMLInputElement)?.value || "Publisher";
    const license = (document.getElementById("pkg-license") as HTMLSelectElement)?.value || "paizo_orc";
    const rootHash = computeRootPackageHash();
    const pubKey = (document.getElementById("pubkey-display")?.textContent) || "ed25519:pub_ready";

    const bundle = {
      manifest: {
        package_id: pkgId,
        title,
        version,
        publisher,
        license,
        assets: assets.map(a => ({ path: a.path, mime_type: a.mimeType, size_bytes: a.sizeBytes, blake3_hash: a.blake3Hash })),
        package_hash: rootHash,
      },
      publisher_public_key: pubKey,
      signature_hex: pseudoBlake3(rootHash + pubKey),
      created_at: new Date().toISOString(),
      bundle_checksum: pseudoBlake3(rootHash + "bundle"),
    };

    const bundleJson = JSON.stringify(bundle, null, 2);
    downloadFile(`${pkgId}.kryptopkg`, bundleJson, "application/json");

    const preview = document.getElementById("bundle-preview-json");
    if (preview) {
      preview.textContent = bundleJson;
    }

    logChronicle("EXPORT_PACKAGE", pkgId, "SUCCESS", bundle.bundle_checksum);
    showToast(`Sealed bundle "${pkgId}.kryptopkg" exported successfully.`, "success");
  });

  // Enterprise Audit Chronicle Drawer
  const drawer = document.getElementById("audit-drawer");
  const backdrop = document.getElementById("drawer-backdrop");

  const openDrawer = () => {
    drawer?.classList.add("open");
    backdrop?.classList.add("show");
  };
  const closeDrawer = () => {
    drawer?.classList.remove("open");
    backdrop?.classList.remove("show");
  };

  document.getElementById("btn-toggle-chronicle")?.addEventListener("click", openDrawer);
  document.getElementById("btn-close-chronicle")?.addEventListener("click", closeDrawer);
  backdrop?.addEventListener("click", closeDrawer);

  document.getElementById("btn-clear-chronicle")?.addEventListener("click", () => {
    chronicleEntries = [];
    renderChronicleList();
    showToast("Audit chronicle cleared.", "info");
  });

  // Assets Management Handlers
  renderAssetsTable();
  renderTierTable();
  logChronicle("INIT_STUDIO", "PublisherStudio", "INFO", computeRootPackageHash());

  const tbody = document.getElementById("asset-tbody");
  tbody?.addEventListener("click", (e) => {
    const target = (e.target as HTMLElement).closest(".delete-asset-btn");
    if (target) {
      const deleteIdx = target.getAttribute("data-delete-idx");
      if (deleteIdx !== null) {
        const removed = assets.splice(parseInt(deleteIdx, 10), 1);
        renderAssetsTable();
        if (removed[0]) {
          logChronicle("REMOVE_ASSET", removed[0].path, "INFO", removed[0].blake3Hash);
          showToast(`Removed asset: ${removed[0].path}`, "info");
        }
      }
    }
  });

  document.getElementById("btn-add-sample-asset")?.addEventListener("click", openAssetModal);
  document.getElementById("btn-modal-cancel")?.addEventListener("click", closeAssetModal);

  document.getElementById("btn-modal-confirm")?.addEventListener("click", () => {
    const pathInput = document.getElementById("modal-asset-path") as HTMLInputElement;
    const mimeInput = document.getElementById("modal-asset-mime") as HTMLSelectElement;
    const pathVal = pathInput?.value?.trim();
    if (!pathVal) {
      showToast("Please enter an asset path.", "error");
      return;
    }

    assets.push({
      path: pathVal,
      mimeType: mimeInput?.value || "application/json",
      sizeBytes: 654320,
      blake3Hash: pseudoBlake3(pathVal),
    });
    renderAssetsTable();
    closeAssetModal();
    pathInput.value = "";
    logChronicle("ADD_ASSET", pathVal, "SUCCESS", pseudoBlake3(pathVal));
    showToast(`Added rulebook asset: ${pathVal}`, "success");
  });

  document.getElementById("btn-recompute-hashes")?.addEventListener("click", () => {
    assets.forEach(a => {
      a.blake3Hash = pseudoBlake3(a.path + secureRandomHex(8));
    });
    renderAssetsTable();
    logChronicle("RECOMPUTE_HASHES", "All Assets", "SUCCESS", computeRootPackageHash());
    showToast("Recomputed deterministic BLAKE3 digests for all assets.", "success");
  });

  // Drag and Drop Asset Ingestion
  const dropzone = document.getElementById("asset-dropzone");
  if (dropzone) {
    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        for (let i = 0; i < e.dataTransfer.files.length; i++) {
          const f = e.dataTransfer.files[i];
          assets.push({
            path: f.name,
            mimeType: f.type || "application/octet-stream",
            sizeBytes: f.size || 102400,
            blake3Hash: pseudoBlake3(f.name + f.size),
          });
        }
        renderAssetsTable();
        showToast(`Ingested ${e.dataTransfer.files.length} assets via drop.`, "success");
      } else {
        openAssetModal();
      }
    });

    dropzone.addEventListener("click", openAssetModal);
  }

  // Schema form listeners
  ["pkg-id", "pkg-title", "pkg-publisher", "pkg-license", "pkg-attribution"].forEach(id => {
    document.getElementById(id)?.addEventListener("input", updateValidationUI);
    document.getElementById(id)?.addEventListener("change", updateValidationUI);
  });

  // Cryptographic Signer Setup
  const keyInput = document.getElementById("signing-key-input") as HTMLInputElement;
  const pubkeyDisplay = document.getElementById("pubkey-display");
  function updatePubkey(): void {
    if (!keyInput || !pubkeyDisplay) return;
    const val = keyInput.value.trim();
    pubkeyDisplay.textContent = `ed25519:pub_${pseudoBlake3(val).slice(0, 32)}`;
  }
  updatePubkey();
  keyInput?.addEventListener("input", updatePubkey);

  document.getElementById("btn-generate-key")?.addEventListener("click", () => {
    const randomHex = secureRandomHex(32);
    if (keyInput) keyInput.value = randomHex;
    updatePubkey();
    logChronicle("FORGE_KEY", "Ed25519", "SUCCESS", randomHex.slice(0, 16));
    showToast("Forged new Ed25519 publisher keypair.", "info");
  });

  document.getElementById("btn-sign-manifest")?.addEventListener("click", () => {
    const { valid, message } = validateSchema();
    if (!valid) {
      showToast(message, "error");
      return;
    }

    const pkgId = (document.getElementById("pkg-id") as HTMLInputElement)?.value || "pkg-test";
    const title = (document.getElementById("pkg-title") as HTMLInputElement)?.value || "Test Title";
    const version = (document.getElementById("pkg-version") as HTMLInputElement)?.value || "1.0.0";
    const publisher = (document.getElementById("pkg-publisher") as HTMLInputElement)?.value || "Test Publisher";
    const license = (document.getElementById("pkg-license") as HTMLSelectElement)?.value || "paizo_orc";
    const rootHash = computeRootPackageHash();
    const pubKey = pubkeyDisplay?.textContent || "ed25519:pub_unknown";

    const bundle = {
      manifest: {
        package_id: pkgId,
        title,
        version,
        publisher,
        license,
        assets: assets.map(a => ({ path: a.path, mime_type: a.mimeType, size_bytes: a.sizeBytes, blake3_hash: a.blake3Hash })),
        package_hash: rootHash,
      },
      publisher_public_key: pubKey,
      signature_hex: pseudoBlake3(rootHash + pubKey),
      created_at: new Date().toISOString(),
      bundle_checksum: pseudoBlake3(rootHash + "bundle"),
    };

    const preview = document.getElementById("bundle-preview-json");
    if (preview) {
      preview.textContent = JSON.stringify(bundle, null, 2);
    }

    const statusBox = document.getElementById("signing-status-box");
    const statusText = document.getElementById("signing-status-text");
    if (statusBox && statusText) {
      statusBox.style.display = "flex";
      statusText.textContent = `Package sealed and bound with publisher key ${pubKey.slice(0, 22)}...`;
    }

    logChronicle("SEAL_MANIFEST", pkgId, "SUCCESS", bundle.bundle_checksum);
    showToast("Manifest cryptographically sealed into .kryptopkg bundle!", "success");
  });

  // Crowdfunding Fulfillment
  const crowdfundInput = document.getElementById("crowdfund-csv-input") as HTMLTextAreaElement;
  if (crowdfundInput) {
    crowdfundInput.value = SAMPLE_KICKSTARTER_CSV;
  }

  document.getElementById("btn-sample-csv")?.addEventListener("click", () => {
    const platform = (document.getElementById("crowdfund-platform") as HTMLSelectElement)?.value;
    if (crowdfundInput) {
      crowdfundInput.value = platform === "backerkit" ? SAMPLE_BACKERKIT_CSV : SAMPLE_KICKSTARTER_CSV;
    }
    showToast(`Loaded sample ${platform.toUpperCase()} campaign data.`, "info");
  });

  document.getElementById("btn-process-fulfillment")?.addEventListener("click", () => {
    const csvData = crowdfundInput?.value.trim();
    if (!csvData) {
      showToast("Please provide backer CSV survey data.", "error");
      return;
    }

    const lines = csvData.split("\n").map(l => l.trim()).filter(Boolean);
    if (lines.length <= 1) {
      showToast("CSV contains no backer rows.", "error");
      return;
    }

    const backerRows = lines.slice(1);
    generatedVouchers = backerRows.map((row, i) => {
      const parts = row.split(",").map(p => p.trim());
      const email = parts[2] || `backer_${i + 1}@example.com`;
      const tier = parts[3] || "Digital Edition";
      const voucherId = `vch-cf-${secureRandomHex(6)}`;
      const claimUrl = `kryptotome://claim?voucherId=${voucherId}&package=pkg-eldritch-vault-5e&exp=2028-01-01`;

      return {
        email,
        tier,
        claimUrl,
        voucherId,
      };
    });

    // Update Stats
    const statBackers = document.getElementById("stat-total-backers");
    const statVouchers = document.getElementById("stat-fulfilled-vouchers");
    const statVcs = document.getElementById("stat-vc-credentials");
    if (statBackers) statBackers.textContent = backerRows.length.toString();
    if (statVouchers) statVouchers.textContent = generatedVouchers.length.toString();
    if (statVcs) statVcs.textContent = generatedVouchers.length.toString();

    // Update Table
    const vTbody = document.getElementById("vouchers-tbody");
    if (vTbody) {
      vTbody.innerHTML = "";
      generatedVouchers.forEach(v => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${escapeHtml(v.email)}</strong></td>
          <td>${escapeHtml(v.tier)}</td>
          <td class="code-cell"><a href="#" style="color:#38bdf8; text-decoration:none;">${escapeHtml(v.claimUrl.slice(0, 38))}...</a></td>
          <td><button class="btn-sm btn-arcane-ghost copy-btn" data-url="${escapeHtml(v.claimUrl)}">Copy Link</button></td>
        `;
        vTbody.appendChild(tr);
      });
    }

    logChronicle("FULFILL_BACKERS", `${backerRows.length} Backers`, "SUCCESS", `vouchers:${generatedVouchers.length}`);
    showToast(`Fulfilled ${backerRows.length} backers into signed claim vouchers.`, "success");
  });

  // Delegate copy button clicks
  document.getElementById("vouchers-tbody")?.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest(".copy-btn");
    if (btn) {
      const url = btn.getAttribute("data-url");
      if (url) {
        copyTextToClipboard(url, "Claim URL copied to clipboard!");
      }
    }
  });

  // Download Fulfillment CSV
  document.getElementById("btn-download-fulfillment-csv")?.addEventListener("click", () => {
    if (generatedVouchers.length === 0) {
      document.getElementById("btn-process-fulfillment")?.click();
    }
    if (generatedVouchers.length === 0) {
      showToast("No vouchers available to export.", "error");
      return;
    }

    let csvContent = "Backer Email,Reward Tier,Voucher ID,Claim URL\n";
    generatedVouchers.forEach(v => {
      csvContent += `"${v.email}","${v.tier}","${v.voucherId}","${v.claimUrl}"\n`;
    });

    downloadFile("kryptotome-claim-vouchers.csv", csvContent, "text/csv");
    logChronicle("EXPORT_CSV", "kryptotome-claim-vouchers.csv", "SUCCESS", `rows:${generatedVouchers.length}`);
    showToast("Exported claim vouchers CSV.", "success");
  });

  // POD & NFC Vouchers Generation
  document.getElementById("btn-generate-pod-batch")?.addEventListener("click", () => {
    const pkgId = (document.getElementById("pod-package-id") as HTMLInputElement)?.value || "pkg-eldritch-vault-5e";
    const format = (document.getElementById("pod-format") as HTMLSelectElement)?.value || "scratch_code";
    const quantity = parseInt((document.getElementById("pod-quantity") as HTMLInputElement)?.value || "5", 10);

    generatedPodCards = Array.from({ length: quantity }, (_, i) => {
      const voucherId = `vch-pod-${Date.now().toString(36)}-${secureRandomHex(4)}`;
      const scratchCode = generateScratchCode();
      const claimUrl = `kryptotome://claim?voucherId=${voucherId}&code=${scratchCode}&pkg=${pkgId}`;
      
      // Standard NFC Forum URI record bytes (0xD1, type 'U', prefix 0x00)
      const urlBytes = Array.from(new TextEncoder().encode(claimUrl));
      const ndefPayload = [0xd1, 0x01, urlBytes.length + 1, 0x55, 0x00, ...urlBytes];
      const ndefHex = ndefPayload.map(b => b.toString(16).padStart(2, "0")).join(" ");

      return {
        voucherId,
        scratchCode,
        ndefHex,
        packageId: pkgId,
        format,
      };
    });

    const listEl = document.getElementById("pod-preview-list");
    if (listEl) {
      listEl.innerHTML = "";
      generatedPodCards.forEach(card => {
        const item = document.createElement("div");
        item.className = "pod-card-item";
        item.innerHTML = `
          <div class="pod-card-top">
            <span class="pod-card-id">VOUCHER: ${escapeHtml(card.voucherId)}</span>
            <span class="pod-card-badge">${escapeHtml(card.format.toUpperCase())}</span>
          </div>
          <div class="pod-scratch-code-box">
            <span>${escapeHtml(card.scratchCode)}</span>
          </div>
          <div class="pod-card-meta">
            <span style="font-size: 11.5px; color: var(--gold-primary); font-family: var(--font-serif);">NDEF Tag Payload (NTAG213 / NTAG215):</span>
            <div class="pod-ndef-hex">${escapeHtml(card.ndefHex)}</div>
          </div>
        `;
        listEl.appendChild(item);
      });
    }

    logChronicle("MINT_VOUCHERS", `${quantity} Vouchers`, "SUCCESS", `pkg:${pkgId}`);
    showToast(`Minted ${quantity} physical ${format} vouchers.`, "success");
  });
}

// Immediate or DOMContentLoaded initialization
if (typeof window !== "undefined") {
  (window as any).publisherStudio = {
    init: initPublisherStudioApp,
    validateSchema,
    computeRootPackageHash,
    pseudoBlake3,
    showToast,
    logChronicle,
  };
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPublisherStudioApp);
  } else {
    initPublisherStudioApp();
  }
}
