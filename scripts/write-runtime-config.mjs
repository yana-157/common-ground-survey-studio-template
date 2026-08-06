import { writeFileSync } from "node:fs";

const rawUrl = process.env.SUPABASE_URL?.trim() ?? "";
const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY?.trim() ?? "";

if (Boolean(rawUrl) !== Boolean(publishableKey)) {
  throw new Error("Add both VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY as GitHub Actions variables, or leave both empty for the setup website.");
}

const config = {};

if (rawUrl && publishableKey) {
  const projectUrl = new URL(rawUrl);
  if (projectUrl.protocol !== "https:" || projectUrl.username || projectUrl.password || projectUrl.search || projectUrl.hash) {
    throw new Error("VITE_SUPABASE_URL must be a plain HTTPS Supabase project address.");
  }
  if (!/^[A-Za-z0-9._-]{20,}$/.test(publishableKey)) {
    throw new Error("VITE_SUPABASE_PUBLISHABLE_KEY does not have the expected browser-safe key format.");
  }
  if (publishableKey.startsWith("sb_secret_")) {
    throw new Error("VITE_SUPABASE_PUBLISHABLE_KEY cannot contain a Supabase secret key.");
  }

  const jwtParts = publishableKey.split(".");
  if (jwtParts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(jwtParts[1], "base64url").toString("utf8"));
      if (payload?.role === "service_role") {
        throw new Error("VITE_SUPABASE_PUBLISHABLE_KEY cannot contain a legacy service-role key.");
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes("service-role")) throw error;
    }
  }

  config.supabaseUrl = projectUrl.toString().replace(/\/$/, "");
  config.supabasePublishableKey = publishableKey;
}

writeFileSync(
  new URL("../site/runtime-config.js", import.meta.url),
  `window.__COMMON_GROUND_CONFIG__ = Object.freeze(${JSON.stringify(config)});\n`,
  "utf8",
);
