import { defineSchema } from "convex/server";

// No tables needed — Lockdown is stateless.
// Password is validated via environment variable.
// All scan actions are ephemeral.
export default defineSchema({});
