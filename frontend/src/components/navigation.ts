/**
 * Navigation model for the shell.
 * Kept as data so the sidebar, page title and active route all share one source.
 */

export type NavIconName =
  | 'overview'
  | 'scans'
  | 'devices'
  | 'controls'
  | 'policies'
  | 'baseline'
  | 'reports'
  | 'ai'
  | 'admin'
  | 'shield';

export interface NavItem {
  path: string;
  label: string;
  hint: string;
  icon: NavIconName;
  /** Only shown to administrators (the API enforces this too). */
  adminOnly?: boolean;
  /** Match child routes (e.g. `/scans/{id}` keeps "Scans" active). */
  matchPrefix?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Monitor',
    items: [
      { path: '/', label: 'Overview', hint: 'Posture at a glance', icon: 'overview' },
      { path: '/scans', label: 'Scans', hint: 'History and detail', icon: 'scans', matchPrefix: true },
      { path: '/devices', label: 'Devices', hint: 'Registered endpoints', icon: 'devices' },
    ],
  },
  {
    label: 'Assess',
    items: [
      { path: '/controls', label: 'Controls', hint: 'Deterministic verdicts', icon: 'controls' },
      { path: '/policies', label: 'Policies', hint: 'Overrides and resolution', icon: 'policies' },
      { path: '/baseline', label: 'Baseline', hint: 'Shipped control pack', icon: 'baseline' },
    ],
  },
  {
    label: 'Insights',
    items: [
      { path: '/reports', label: 'Reports', hint: 'HTML and PDF artefacts', icon: 'reports' },
      { path: '/ai', label: 'AI Assistant', hint: 'Advisory explanations', icon: 'ai' },
    ],
  },
  {
    label: 'Platform',
    items: [
      { path: '/admin', label: 'Administration', hint: 'Users and audit trail', icon: 'admin', adminOnly: true },
      {
        path: '/admin/security-policy',
        label: 'Security Policy',
        hint: 'Effective platform policy',
        icon: 'shield',
        adminOnly: true,
      },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((group) => group.items);

/** Longest-prefix match so `/scans/abc` resolves to the Scans entry. */
export function findNavItem(pathname: string): NavItem | undefined {
  const candidates = NAV_ITEMS.filter((item) =>
    item.path === '/' ? pathname === '/' : pathname === item.path || pathname.startsWith(`${item.path}/`),
  );
  return candidates.sort((a, b) => b.path.length - a.path.length)[0];
}
