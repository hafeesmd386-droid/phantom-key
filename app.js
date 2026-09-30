"use strict";

const MAGIC = new Uint8Array([0x50, 0x48, 0x4b, 0x45, 0x59, 0x01]);
const DEFAULT_ITERATIONS = 600_000;
const MAX_ITERATIONS = 5_000_000;
const MAX_FILE_SIZE = 128 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const elements = {
  runtimeStatus: document.querySelector("#runtimeStatus"),
  tabs: [...document.querySelectorAll("[data-mode]")],
  operationIndex: document.querySelector("#operationIndex"),
  operationTitle: document.querySelector("#operationTitle"),
  dropZone: document.querySelector("#dropZone"),
  dropTitle: document.querySelector("#dropTitle"),
  dropSubtitle: document.querySelector("#dropSubtitle"),
  fileInput: document.querySelector("#fileInput"),
  chooseFile: document.querySelector("#chooseFile"),
  selectedFile: document.querySelector("#selectedFile"),
  selectedName: document.querySelector("#selectedName"),
  selectedMeta: document.querySelector("#selectedMeta"),
  removeFile: document.querySelector("#removeFile"),
  passwordInput: document.querySelector("#passwordInput"),
  revealPassword: document.querySelector("#revealPassword"),
  generatePassword: document.querySelector("#generatePassword"),
  strengthTrack: document.querySelector("#strengthTrack"),
  strengthLabel: document.querySelector("#strengthLabel"),
  processButton: document.querySelector("#processButton"),
  processLabel: document.querySelector("#processLabel"),
  operationNote: document.querySelector("#operationNote"),
  result: document.querySelector("#result"),
  sessionLabel: document.querySelector("#sessionLabel"),
  sessionState: document.querySelector(".session-state"),
  sessionDetail: document.querySelector("#sessionDetail"),
};

let mode = "protect";
let selectedFile = null;

function concatBytes(...parts) {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) throw new Error("This is not a valid Phantom Key file.");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/g, "");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function deriveRawKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    256,
  ));
}

async function fernetKeys(rawKey) {
  const signingKey = await crypto.subtle.importKey("raw", rawKey.subarray(0, 16), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const encryptionKey = await crypto.subtle.importKey("raw", rawKey.subarray(16), { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
  return { signingKey, encryptionKey };
}

function buildPayload(name, data) {
  const encodedName = encoder.encode(name);
  if (encodedName.length > 0xffff) throw new Error("This file name is too long.");
  const nameLength = new Uint8Array(2);
  new DataView(nameLength.buffer).setUint16(0, encodedName.length, false);
  return concatBytes(nameLength, encodedName, data);
}

async function protectBytes(file, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const rawKey = await deriveRawKey(password, salt, DEFAULT_ITERATIONS);
  const { signingKey, encryptionKey } = await fernetKeys(rawKey);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const payload = buildPayload(file.name, new Uint8Array(await file.arrayBuffer()));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, encryptionKey, payload));

  const fernetBody = new Uint8Array(25 + ciphertext.length);
  fernetBody[0] = 0x80;
  new DataView(fernetBody.buffer).setBigUint64(1, BigInt(Math.floor(Date.now() / 1000)), false);
  fernetBody.set(iv, 9);
  fernetBody.set(ciphertext, 25);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", signingKey, fernetBody));
  const token = encoder.encode(bytesToBase64Url(concatBytes(fernetBody, signature)));

  const header = new Uint8Array(26);
  header.set(MAGIC, 0);
  new DataView(header.buffer).setUint32(6, DEFAULT_ITERATIONS, false);
  header.set(salt, 10);
  return concatBytes(header, token);
}

async function restoreBytes(blob, password) {
  if (blob.length <= 26 || !MAGIC.every((byte, index) => blob[index] === byte)) {
    throw new Error("Not a valid .phkey file (bad header).");
  }

  const header = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const iterations = header.getUint32(6, false);
  if (iterations < 1 || iterations > MAX_ITERATIONS) {
    throw new Error("This file uses an unsupported PBKDF2 work factor.");
  }
  const salt = blob.subarray(10, 26);
  const tokenText = decoder.decode(blob.subarray(26));
  const token = base64UrlToBytes(tokenText);
  if (token.length < 73 || token[0] !== 0x80) throw new Error("Not a valid Fernet token.");

  const body = token.subarray(0, token.length - 32);
  const signature = token.subarray(token.length - 32);
  const rawKey = await deriveRawKey(password, salt, iterations);
  const { signingKey, encryptionKey } = await fernetKeys(rawKey);
  const authentic = await crypto.subtle.verify("HMAC", signingKey, signature, body);
  if (!authentic) throw new Error("Authentication failed: wrong passphrase or file modified.");

  const iv = body.subarray(9, 25);
  let payload;
  try {
    payload = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, encryptionKey, body.subarray(25)));
  } catch {
    throw new Error("Authentication failed: wrong passphrase or file modified.");
  }
  if (payload.length < 2) throw new Error("The decrypted payload is incomplete.");
  const nameLength = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint16(0, false);
  if (nameLength > payload.length - 2) throw new Error("The decrypted file name is invalid.");
  const name = decoder.decode(payload.subarray(2, 2 + nameLength));
  const safeName = name.split(/[\\/]/).filter(Boolean).pop() || "restored-file";
  return { name: safeName, data: payload.slice(2 + nameLength), iterations };
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let size = bytes / 1024;
  let unit = units[0];
  for (let index = 1; size >= 1024 && index < units.length; index += 1) {
    size /= 1024;
    unit = units[index];
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${unit}`;
}

function clearResult() {
  elements.result.hidden = true;
  elements.result.classList.remove("is-error");
  elements.result.replaceChildren();
}

function setResult(message, kind = "success", download = null) {
  clearResult();
  elements.result.hidden = false;
  elements.result.classList.toggle("is-error", kind === "error");
  const text = document.createElement("span");
  text.textContent = message;
  elements.result.append(text);
  if (download) {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(download.blob);
    link.download = download.name;
    link.textContent = "Download file";
    link.addEventListener("click", () => setTimeout(() => URL.revokeObjectURL(link.href), 60_000), { once: true });
    elements.result.append(link);
  }
}

function analyzePassword(password) {
  if (!password) return { score: 0, label: "NO PASSPHRASE" };
  const checks = [password.length >= 12, /[A-Z]/.test(password), /[a-z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)];
  let score = checks.filter(Boolean).length + (password.length >= 16 ? 1 : 0);
  if (["123456", "password", "qwerty", "admin", "letmein", "12345678", "admin123"].includes(password.toLowerCase())) score = 0;
  if (score <= 2) return { score: 1, label: "WEAK" };
  if (score <= 4) return { score: 2, label: "FAIR" };
  if (score === 5) return { score: 3, label: "GOOD" };
  return { score: 4, label: "STRONG" };
}

function updateStrength() {
  const result = analyzePassword(elements.passwordInput.value);
  elements.strengthTrack.dataset.score = String(result.score);
  elements.strengthLabel.textContent = result.label;
}

function updateActionState() {
  elements.processButton.disabled = !selectedFile || !elements.passwordInput.value || !window.isSecureContext || !crypto.subtle;
}

function setSelectedFile(file) {
  clearResult();
  if (!file) {
    selectedFile = null;
    elements.fileInput.value = "";
    elements.selectedFile.hidden = true;
    elements.dropZone.hidden = false;
    elements.sessionLabel.textContent = "READY";
    elements.sessionDetail.textContent = "No file selected";
    elements.sessionState.classList.remove("is-ready");
    updateActionState();
    return;
  }
  if (file.size > MAX_FILE_SIZE) {
    setResult("Files must be 128 MB or smaller.", "error");
    return;
  }
  if (mode !== "protect" && !file.name.toLowerCase().endsWith(".phkey")) {
    setResult("Choose a .phkey file to restore or verify.", "error");
    return;
  }
  selectedFile = file;
  elements.selectedName.textContent = file.name;
  elements.selectedMeta.textContent = `${formatBytes(file.size)}  ·  ${file.type || "FILE"}`;
  elements.selectedFile.hidden = false;
  elements.dropZone.hidden = true;
  elements.sessionLabel.textContent = "FILE READY";
  elements.sessionDetail.textContent = file.name;
  elements.sessionState.classList.add("is-ready");
  updateActionState();
}

function setMode(nextMode) {
  mode = nextMode;
  const isProtect = mode === "protect";
  const isRestore = mode === "restore";
  const labels = {
    protect: ["01", "Protect a file", "Choose a file to protect", "Any file type", "Protect file"],
    restore: ["02", "Restore a file", "Choose a .phkey file", ".phkey files", "Restore file"],
    verify: ["03", "Verify a file", "Choose a .phkey file", ".phkey files", "Verify file"],
  }[mode];
  elements.tabs.forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.setAttribute("tabindex", active ? "0" : "-1");
  });
  elements.operationIndex.textContent = `OPERATION ${labels[0]}`;
  elements.operationTitle.textContent = labels[1];
  elements.dropTitle.textContent = labels[2];
  elements.dropSubtitle.innerHTML = `${labels[3]} <b>·</b> Up to 128 MB`;
  elements.processLabel.textContent = labels[4];
  elements.operationNote.innerHTML = isProtect
    ? "PBKDF2-SHA256 <b>·</b> 600,000 rounds"
    : "PBKDF2-SHA256 <b>·</b> file-defined rounds";
  elements.fileInput.accept = isProtect ? "*/*" : ".phkey,application/octet-stream";
  elements.fileInput.value = "";
  setSelectedFile(null);
  elements.passwordInput.value = "";
  updateStrength();
  updateActionState();
  clearResult();
}

function randomIndex(max) {
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const value = new Uint32Array(1);
  do crypto.getRandomValues(value); while (value[0] >= limit);
  return value[0] % max;
}

function makePassword(length = 20) {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = "!@#$%^&*()-_=+[]{};:,.<>?/";
  const alphabet = lower + upper + digits + symbols;
  const chars = [lower[randomIndex(lower.length)], upper[randomIndex(upper.length)], digits[randomIndex(digits.length)], symbols[randomIndex(symbols.length)]];
  while (chars.length < length) chars.push(alphabet[randomIndex(alphabet.length)]);
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [chars[index], chars[swapIndex]] = [chars[swapIndex], chars[index]];
  }
  return chars.join("");
}

async function processFile() {
  if (!selectedFile || !elements.passwordInput.value) return;
  clearResult();
  elements.processButton.disabled = true;
  elements.processLabel.textContent = mode === "protect" ? "Protecting…" : mode === "restore" ? "Restoring…" : "Verifying…";
  elements.sessionLabel.textContent = "PROCESSING";
  elements.sessionState.classList.remove("is-ready");
  try {
    const password = elements.passwordInput.value;
    if (mode === "protect") {
      const protectedBytes = await protectBytes(selectedFile, password);
      const outputName = `${selectedFile.name}.phkey`;
      setResult("File protected. The original file was not changed.", "success", {
        name: outputName,
        blob: new Blob([protectedBytes], { type: "application/octet-stream" }),
      });
      elements.sessionLabel.textContent = "PROTECTED";
    } else {
      const restored = await restoreBytes(new Uint8Array(await selectedFile.arrayBuffer()), password);
      if (mode === "restore") {
        setResult("File restored successfully.", "success", {
          name: restored.name,
          blob: new Blob([restored.data], { type: "application/octet-stream" }),
        });
        elements.sessionLabel.textContent = "RESTORED";
      } else {
        setResult(`Passphrase verified · ${formatBytes(restored.data.length)} authenticated.`);
        elements.sessionLabel.textContent = "VERIFIED";
      }
    }
    elements.sessionState.classList.add("is-ready");
  } catch (error) {
    setResult(error instanceof Error ? error.message : "The operation could not be completed.", "error");
    elements.sessionLabel.textContent = "CHECK FAILED";
    elements.sessionState.classList.remove("is-ready");
  } finally {
    elements.processLabel.textContent = { protect: "Protect file", restore: "Restore file", verify: "Verify file" }[mode];
    updateActionState();
  }
}

elements.tabs.forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));
elements.chooseFile.addEventListener("click", (event) => {
  event.stopPropagation();
  elements.fileInput.click();
});
elements.dropZone.addEventListener("click", (event) => {
  if (event.target !== elements.chooseFile) elements.fileInput.click();
});
elements.fileInput.addEventListener("change", () => setSelectedFile(elements.fileInput.files[0] || null));
elements.removeFile.addEventListener("click", () => setSelectedFile(null));
elements.passwordInput.addEventListener("input", () => {
  updateStrength();
  updateActionState();
});
elements.revealPassword.addEventListener("click", () => {
  const reveal = elements.passwordInput.type === "password";
  elements.passwordInput.type = reveal ? "text" : "password";
  elements.revealPassword.setAttribute("aria-label", reveal ? "Hide passphrase" : "Show passphrase");
  elements.revealPassword.title = reveal ? "Hide passphrase" : "Show passphrase";
});
elements.generatePassword.addEventListener("click", () => {
  elements.passwordInput.value = makePassword();
  updateStrength();
  updateActionState();
  elements.passwordInput.focus();
});
elements.processButton.addEventListener("click", processFile);
elements.dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  elements.dropZone.classList.add("is-dragging");
});
elements.dropZone.addEventListener("dragleave", () => elements.dropZone.classList.remove("is-dragging"));
elements.dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  elements.dropZone.classList.remove("is-dragging");
  setSelectedFile(event.dataTransfer.files[0] || null);
});

if (window.isSecureContext && crypto.subtle) {
  elements.runtimeStatus.classList.add("is-ready");
  elements.runtimeStatus.lastElementChild.textContent = "CRYPTO READY";
} else {
  elements.runtimeStatus.classList.add("is-error");
  elements.runtimeStatus.lastElementChild.textContent = "HTTPS REQUIRED";
  setResult("Open this page over HTTPS or localhost to use browser cryptography.", "error");
}
setMode("protect");