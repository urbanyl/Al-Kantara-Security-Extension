/**
 * Al-Kantara Security — Storage Manager
 * Manages extension storage with JSON Schema validation.
 * Provides a clean async API over chrome.storage.local / browser.storage.local.
 *
 * © Urbanyl — github.com/urbanyl
 */

(function () {
  "use strict";

  const _api = typeof browser !== "undefined" ? browser : chrome;

  const STORAGE_SCHEMA = {
    aks_active_profile:      { type: "string",  enum: ["strict", "moderate", "disabled"] },
    aks_kill_switch:         { type: "boolean" },
    aks_fingerprint_persona: { type: "string",  enum: ["win11_edge", "macos_safari", "linux_firefox", "win10_chrome", "android_chrome", "ios_safari"] },
    aks_dns_protection:      { type: "boolean" },
    aks_webrtc_mode:         { type: "string",  enum: ["disabled", "force_proxy", "block"] },
    aks_header_overrides:    { type: "array" },
    aks_event_logs:          { type: "array" },
    aks_last_chemical_clean: { type: ["string", "null"] },
    aks_user_settings: {
      type: "object",
      properties: {
        chemicalCleanOnStart: { type: "boolean" },
        autoCleanInterval:    { type: "number" },
        logRetentionDays:     { type: "number" },
        showNotifications:    { type: "boolean" }
      }
    }
  };

  function validate(value, schema) {
    if (schema === undefined || schema === null) return true;
    if (schema === "string")  return typeof value === "string";
    if (schema === "boolean") return typeof value === "boolean";
    if (schema === "number")  return typeof value === "number";
    if (schema === "array")   return Array.isArray(value);

    if (Array.isArray(schema.enum)) {
      return schema.enum.includes(value);
    }

    if (schema.type === "string" && Array.isArray(schema.enum)) {
      return schema.enum.includes(value);
    }

    if (schema.type === "object" && schema.properties) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
      for (const [key, subSchema] of Object.entries(schema.properties)) {
        if (value[key] !== undefined && !validate(value[key], subSchema)) return false;
      }
      return true;
    }

    if (Array.isArray(schema.type)) {
      return schema.type.some(t => validate(value, { type: t }));
    }

    return true;
  }

  const AKSStorage = {
    async get(key) {
      try {
        const result = await _api.storage.local.get(key);
        return result[key] !== undefined ? result[key] : null;
      } catch (e) {
        console.error("[AKS Storage] Get failed:", e);
        return null;
      }
    },

    async set(key, value) {
      const schema = STORAGE_SCHEMA[key];
      if (schema && !validate(value, schema)) {
        console.error(`[AKS Storage] Validation failed for key '${key}':`, value);
        return false;
      }
      try {
        await _api.storage.local.set({ [key]: value });
        return true;
      } catch (e) {
        console.error("[AKS Storage] Set failed:", e);
        return false;
      }
    },

    async getMultiple(keys) {
      try {
        return await _api.storage.local.get(keys);
      } catch (e) {
        console.error("[AKS Storage] GetMultiple failed:", e);
        return {};
      }
    },

    async setMultiple(obj) {
      const validated = {};
      for (const [key, value] of Object.entries(obj)) {
        const schema = STORAGE_SCHEMA[key];
        if (schema && !validate(value, schema)) {
          console.error(`[AKS Storage] Validation failed for key '${key}'`);
          continue;
        }
        validated[key] = value;
      }
      try {
        await _api.storage.local.set(validated);
        return true;
      } catch (e) {
        console.error("[AKS Storage] SetMultiple failed:", e);
        return false;
      }
    },

    async remove(key) {
      try {
        await _api.storage.local.remove(key);
        return true;
      } catch (e) {
        console.error("[AKS Storage] Remove failed:", e);
        return false;
      }
    },

    async clear() {
      try {
        const protectedKeys = ["aks_active_profile", "aks_kill_switch", "aks_fingerprint_persona"];
        const existing = await _api.storage.local.get(protectedKeys);
        await _api.storage.local.clear();
        await _api.storage.local.set(existing);
        return true;
      } catch (e) {
        console.error("[AKS Storage] Clear failed:", e);
        return false;
      }
    },

    validate(key, value) {
      const schema = STORAGE_SCHEMA[key];
      if (!schema) return true;
      return validate(value, schema);
    }
  };

  if (typeof window !== "undefined") {
    window.AKSStorage = AKSStorage;
  }
})();
