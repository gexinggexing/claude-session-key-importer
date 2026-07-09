import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async (command: string) => {
    if (command === "scan_profiles") {
      return [
        {
          id: "chrome:Default",
          browser: "Chrome",
          profile_name: "Default",
          profile_path: "/tmp/Profile",
          cookies_db_path: "/tmp/Profile/Network/Cookies",
          exists: true,
          cookies_db_exists: true,
          is_locked_suspected: false,
          is_running: false,
          cdp_endpoint: null,
        },
      ];
    }
    return null;
  }),
}));

describe("App", () => {
  it("renders profile scanning and import controls", async () => {
    render(<App />);

    expect(await screen.findByText("Claude Session Key Importer")).toBeInTheDocument();
    expect(await screen.findByText("Chrome")).toBeInTheDocument();
    expect(screen.getByLabelText(/Session input/i)).toBeInTheDocument();
    expect(screen.getByText(/Direct SQLite/i)).toBeInTheDocument();
  });
});

