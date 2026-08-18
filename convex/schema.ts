import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

// Scans themselves are ephemeral — findings are returned to the caller and
// never stored. The one table here exists solely to rate-limit callers, which
// cannot be done statelessly.
export default defineSchema({
  scanEvents: defineTable({
    caller: v.string(),   // coarse caller key, not an identity
    at: v.number(),       // epoch ms
  }).index("by_caller_at", ["caller", "at"]),
});
