const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

async function readErrorDetail(response) {
  try {
    const data = await response.json();
    if (typeof data?.detail === "string") return data.detail;
    if (Array.isArray(data?.detail)) return data.detail.map((d) => d.msg || d).join("; ");
    return JSON.stringify(data);
  } catch {
    return response.statusText;
  }
}

async function apiFetch(path, options = {}) {
  const url = `${API_BASE}${path}`;
  let response;
  try {
    response = await fetch(url, options);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(
      `Cannot reach API at ${API_BASE}. Start it with: python -m uvicorn hackon.backend.api.main:app --host 127.0.0.1 --port 8000 (${msg})`
    );
  }
  return response;
}

export async function createScan(payload) {
  const response = await apiFetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error(`Failed to create scan (${response.status}): ${await readErrorDetail(response)}`);
  }
  return response.json();
}

export async function getScanStatus(scanId) {
  const response = await apiFetch(`/api/scans/${scanId}`);
  if (!response.ok) {
    throw new Error(`Failed to read scan status (${response.status}): ${await readErrorDetail(response)}`);
  }
  return response.json();
}

export async function getScanResult(scanId) {
  const response = await apiFetch(`/api/scans/${scanId}/result`);
  if (!response.ok) {
    throw new Error(`Failed to get scan result (${response.status}): ${await readErrorDetail(response)}`);
  }
  return response.json();
}

export function getApiBase() {
  return API_BASE;
}
