export type User = { username: string; role: string };
export type Token = User;

export type Analytics = {
  total_scans: number;
  incidents: number;
  blocked: number;
  masked: number;
  reviewed: number;
  high_risk: number;
  average_risk: number;
  trends: { date: string; scans: number; blocked: number; masked: number }[];
  category_counts: Record<string, number>;
};

export type Incident = {
  id: number;
  source: string;
  destination: string;
  categories: string[];
  finding_counts: Record<string, number>;
  risk_factors: { label: string; points: number }[];
  risk_score: number;
  severity: string;
  decision: string;
  recommended_action: string;
  status: string;
  masked_preview: string;
  created_at: string;
};

export type Policy = {
  id: number;
  category: string;
  action: "mask" | "block";
  weight: number;
  description: string;
  enabled: boolean;
};

export type ScanResult = {
  incident_id: number | null;
  decision: "allow" | "mask" | "block" | "review";
  risk_score: number;
  severity: string;
  findings: {
    category: string;
    count: number;
    masked_examples: string[];
    confidence: number;
    explanation: string;
  }[];
  risk_factors: { label: string; points: number }[];
  protected_preview: string;
  recommended_action: string;
  message: string;
  filename?: string;
  extraction_method?: string;
  extracted_characters?: number;
  truncated?: boolean;
};

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/+$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    readonly fieldErrors: Record<string, string> = {},
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function readCsrfToken(): string | undefined {
  return document.cookie
    .split("; ")
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith("csrf_token="))
    ?.split("=")[1];
}

export async function api<T>(
  path: string,
  token?: string,
  options: RequestInit = {},
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);
  if (typeof options.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    const csrfToken = readCsrfToken();
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: "include",
    headers,
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as
      | { detail?: string; field_errors?: Record<string, string> }
      | null;
    throw new ApiError(
      body?.detail ?? `Request failed (${response.status})`,
      body?.field_errors ?? {},
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function downloadIncidentReport(token?: string): Promise<void> {
  const headers = new Headers();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}/incidents/report.csv`, {
    credentials: "include",
    headers,
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new ApiError(body?.detail ?? `Report download failed (${response.status})`);
  }
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = "privexai-incidents.csv";
  link.click();
  URL.revokeObjectURL(url);
}
