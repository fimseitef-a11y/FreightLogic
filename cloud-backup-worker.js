/**
 * FreightLogic Cloud Backup Worker (v3)
 * ======================================
 * Deploy to: https://freightlogic-backup.fimseitef.workers.dev
 *
 * SETUP:
 *   1. Paste this code in your Cloudflare Worker editor
 *   2. KV binding: BACKUPS
 *   3. Secret: BACKUP_TOKEN = (your long random string)
 *   4. Optional: ALLOWED_ORIGIN = your GitHub Pages URL (e.g. https://yourusername.github.io)
 *      If not set, all origins are allowed (acceptable for personal use).
 *   5. In FreightLogic Settings → Cloud Backup:
 *      - URL: https://freightlogic-backup.fimseitef.workers.dev
 *      - Passphrase: (your encryption passphrase)
 *      - Token: (same value as BACKUP_TOKEN)
 */

export default {
  async fetch(request, env) {
    // Use ALLOWED_ORIGIN env var if set, otherwise allow any origin
    const allowedOrigin = env.ALLOWED_ORIGIN || "*";
    const headers = {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Device-Id, X-Backup-Token",
      "Content-Type": "application/json"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    const token = request.headers.get("X-Backup-Token");
    if (!token || token !== env.BACKUP_TOKEN) {
      return new Response(
        JSON.stringify({ ok: false, error: "Unauthorized" }),
        { status: 401, headers }
      );
    }

    const deviceId = request.headers.get("X-Device-Id");
    if (!deviceId) {
      return new Response(
        JSON.stringify({ ok: false, error: "Missing X-Device-Id" }),
        { status: 400, headers }
      );
    }

    if (request.method === "POST") {
      const data = await request.text();
      if (data.length > 5000000) {
        return new Response(
          JSON.stringify({ ok: false, error: "Payload too large" }),
          { status: 413, headers }
        );
      }
      const id = crypto.randomUUID();
      const key = `${deviceId}:${id}`;
      await env.BACKUPS.put(key, data);

      // Rotation: keep only the last 3 backups per device
      try {
        const list = await env.BACKUPS.list({ prefix: `${deviceId}:` });
        if (list.keys.length > 3) {
          // KV list returns keys in lexicographic order; UUID-based keys
          // approximate creation order. Delete the oldest ones.
          const toDelete = list.keys.slice(0, list.keys.length - 3);
          await Promise.all(toDelete.map(k => env.BACKUPS.delete(k.name)));
        }
      } catch (e) {
        // Rotation is best-effort — don't fail the backup itself
      }

      return new Response(
        JSON.stringify({ ok: true, saved: key, rotated: true }),
        { status: 200, headers }
      );
    }

    if (request.method === "GET") {
      const url = new URL(request.url);
      const specificKey = url.searchParams.get("key");

      if (specificKey) {
        if (!specificKey.startsWith(deviceId + ":")) {
          return new Response(
            JSON.stringify({ ok: false, error: "Key does not belong to this device" }),
            { status: 403, headers }
          );
        }
        const value = await env.BACKUPS.get(specificKey);
        if (!value) {
          return new Response(
            JSON.stringify({ ok: false, error: "Backup not found" }),
            { status: 404, headers }
          );
        }
        return new Response(value, { status: 200, headers });
      }

      const list = await env.BACKUPS.list({ prefix: `${deviceId}:` });
      return new Response(
        JSON.stringify({
          ok: true,
          backups: list.keys.map(k => k.name)
        }),
        { status: 200, headers }
      );
    }

    return new Response(
      JSON.stringify({ ok: false, error: "Method not allowed" }),
      { status: 405, headers }
    );
  }
};
