export type User = { username: string; role: string };
export type Token = User & { access_token: string; token_type: string };

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
  findings: { category: string; count: number; masked_examples: string[] }[];
  risk_factors: { label: string; points: number }[];
  protected_preview: string;
  recommended_action: string;
  message: string;
};

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/+$/, "");

export async function api<T>(
  path: string,
  token?: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as
      | { detail?: string }
      | null;
    throw new Error(body?.detail ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}
