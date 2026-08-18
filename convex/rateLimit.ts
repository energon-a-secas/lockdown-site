import { internalMutation } from "./_generated/server";
import { v } from "convex/values";

/** Scans allowed per caller per window. */
const MAX_SCANS = 12;
const WINDOW_MS = 5 * 60 * 1000;

/**
 * Records one scan and reports whether the caller is over budget.
 *
 * Actions cannot touch the database directly, so the public scanner actions
 * reach this through ctx.runMutation. Returns rather than throws so the
 * action decides the user-facing message.
 */
export const recordAndCheck = internalMutation({
  args: { caller: v.string() },
  handler: async (ctx, { caller }) => {
    const cutoff = Date.now() - WINDOW_MS;

    const recent = await ctx.db
      .query("scanEvents")
      .withIndex("by_caller_at", (q) => q.eq("caller", caller).gte("at", cutoff))
      .collect();

    // Drop anything already outside the window so the table stays bounded.
    const stale = await ctx.db
      .query("scanEvents")
      .withIndex("by_caller_at", (q) => q.eq("caller", caller).lt("at", cutoff))
      .collect();
    for (const row of stale) await ctx.db.delete(row._id);

    if (recent.length >= MAX_SCANS) {
      return { allowed: false, used: recent.length, max: MAX_SCANS, windowMs: WINDOW_MS };
    }

    await ctx.db.insert("scanEvents", { caller, at: Date.now() });
    return { allowed: true, used: recent.length + 1, max: MAX_SCANS, windowMs: WINDOW_MS };
  },
});
