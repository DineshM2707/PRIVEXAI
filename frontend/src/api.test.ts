import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("adds JSON and bearer headers to authenticated requests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await api<{ status: string }>("/health", "signed-token", {
      method: "POST",
      body: JSON.stringify({ sample: true }),
    });

    expect(result).toEqual({ status: "ok" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(options.headers);
    expect(url).toBe("/api/health");
    expect(options.method).toBe("POST");
    expect(headers.get("Authorization")).toBe("Bearer signed-token");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("surfaces API validation errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "Sample text is required." }), {
          status: 422,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(api("/scans", "signed-token")).rejects.toThrow(
      "Sample text is required.",
    );
  });
});
