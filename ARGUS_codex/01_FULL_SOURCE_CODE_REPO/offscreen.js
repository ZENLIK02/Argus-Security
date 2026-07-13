"use strict";

const HASH_MESSAGE = "ARGUS_HASH_IMAGE";
const MAX_IMAGE_BYTES = 512 * 1024;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== HASH_MESSAGE) return false;
  hashImageUrl(message.url)
    .then((hash) => sendResponse({ ok: Boolean(hash), hash }))
    .catch(() => sendResponse({ ok: false, hash: null }));
  return true;
});

async function hashImageUrl(value) {
  const parsed = new URL(String(value || ""));
  if (parsed.protocol !== "https:") return null;
  const response = await fetch(parsed.toString(), { credentials: "omit", redirect: "follow", cache: "force-cache" });
  if (!response.ok || !/^image\//i.test(response.headers.get("content-type") || "")) return null;
  const declared = Number(response.headers.get("content-length")) || 0;
  if (declared > MAX_IMAGE_BYTES) return null;
  const bytes = await readLimited(response.body, MAX_IMAGE_BYTES);
  if (!bytes) return null;
  const bitmap = await createImageBitmap(new Blob([bytes], { type: response.headers.get("content-type") || "image/png" }));
  const canvas = new OffscreenCanvas(9, 8);
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.clearRect(0, 0, 9, 8);
  context.drawImage(bitmap, 0, 0, 9, 8);
  bitmap.close();
  const pixels = context.getImageData(0, 0, 9, 8).data;
  let hash = 0n;
  for (let y = 0; y < 8; y += 1) {
    for (let x = 0; x < 8; x += 1) {
      const left = grayscale(pixels, (y * 9 + x) * 4);
      const right = grayscale(pixels, (y * 9 + x + 1) * 4);
      hash = (hash << 1n) | (left > right ? 1n : 0n);
    }
  }
  return hash.toString(16).padStart(16, "0");
}

async function readLimited(stream, limit) {
  if (!stream || typeof stream.getReader !== "function") return null;
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

function grayscale(data, offset) {
  return data[offset] * 0.299 + data[offset + 1] * 0.587 + data[offset + 2] * 0.114;
}
