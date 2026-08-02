export interface ToolCategory {
  name: string;
  pattern: RegExp;
  description: string;
  requiresOrgMode?: boolean;
}

// HARDENED: presets reduced to mail + calendar only. Upstream presets for
// files/excel/teams/sharepoint/contacts/tasks/onenote/search/users have been
// removed in sync with the endpoints.json filtering (see PLAN.md §8).
export const TOOL_CATEGORIES: Record<string, ToolCategory> = {
  mail: {
    name: 'mail',
    pattern: /mail|attachment|draft|message/i,
    description: 'Email operations (read, send, manage folders, attachments)',
  },
  calendar: {
    name: 'calendar',
    pattern: /calendar|event/i,
    description: 'Calendar and event management',
  },
  all: {
    name: 'all',
    pattern: /.*/,
    description: 'All available tools (mail + calendar)',
  },
};

export function getCombinedPresetPattern(presets: string[]): string {
  const patterns = presets.map((preset) => {
    // HARDENED: `preset` is user-supplied (CLI/env). Guard with hasOwnProperty
    // to block prototype-chain keys (__proto__, constructor…) even though
    // TOOL_CATEGORIES is a small closed record.
    const category = Object.prototype.hasOwnProperty.call(TOOL_CATEGORIES, preset)
      ? // eslint-disable-next-line security/detect-object-injection -- justif: accès gardé par Object.prototype.hasOwnProperty.call ci-dessus — le ternaire court-circuite sur undefined pour toute clé non-own (bloque __proto__/constructor). eslint ne voit pas la garde statiquement.
        TOOL_CATEGORIES[preset]
      : undefined;
    if (!category) {
      throw new Error(
        `Unknown preset: ${preset}. Available presets: ${Object.keys(TOOL_CATEGORIES).join(', ')}`
      );
    }
    return category.pattern.source;
  });
  return patterns.join('|');
}

export function listPresets(): Array<{
  name: string;
  description: string;
  requiresOrgMode?: boolean;
}> {
  return Object.values(TOOL_CATEGORIES).map((category) => ({
    name: category.name,
    description: category.description,
    requiresOrgMode: category.requiresOrgMode,
  }));
}

export function presetRequiresOrgMode(preset: string): boolean {
  // HARDENED: `preset` is user-supplied. Guard with hasOwnProperty to block
  // prototype-chain keys (__proto__, constructor…). Same rationale as
  // getCombinedPresetPattern above.
  const category = Object.prototype.hasOwnProperty.call(TOOL_CATEGORIES, preset)
    ? // eslint-disable-next-line security/detect-object-injection -- justif: accès gardé par Object.prototype.hasOwnProperty.call ci-dessus — le ternaire court-circuite sur undefined pour toute clé non-own (bloque __proto__/constructor). eslint ne voit pas la garde statiquement.
      TOOL_CATEGORIES[preset]
    : undefined;
  return category?.requiresOrgMode || false;
}
