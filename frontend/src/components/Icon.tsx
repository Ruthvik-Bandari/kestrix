// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import {
  ArrowLeft,
  ArrowRight,
  Bitcoin,
  Braces,
  BookOpen,
  Bot,
  Check,
  ChartNoAxesColumn,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleMinus,
  CircleQuestionMark,
  CircleX,
  Clock,
  Copy,
  Download,
  ExternalLink,
  File,
  FileSearch,
  FileText,
  FingerprintPattern,
  Gauge,
  Globe,
  GlobeLock,
  Info,
  KeyRound,
  LayoutGrid,
  Link2,
  ListChecks,
  Lock,
  LogOut,
  Mail,
  MailWarning,
  MapPin,
  Menu,
  Monitor,
  Moon,
  OctagonAlert,
  Package,
  Play,
  RotateCcwClock,
  Route,
  ScanSearch,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sparkle,
  Sun,
  Terminal,
  Trash,
  TriangleAlert,
  Upload,
  Wrench,
  X,
  type LucideIcon,
} from "lucide-react";

/*
 * Every icon in the app is a Lucide icon (lucide-react, ISC; see NOTICE), named here once.
 * Named imports keep the bundle to the icons listed. Brand logos (Google, GitHub) are not
 * Lucide icons: they live in features/auth/providers.tsx.
 */
const icons = {
  shield: Shield,
  shieldCheck: ShieldCheck,
  check: Check,
  checkCircle: CircleCheck,
  x: X,
  xCircle: CircleX,
  alert: TriangleAlert,
  octagon: OctagonAlert,
  info: Info,
  minus: CircleMinus,
  help: CircleQuestionMark,
  copy: Copy,
  download: Download,
  upload: Upload,
  file: File,
  fileText: FileText,
  fileSearch: FileSearch,
  globe: Globe,
  globeLock: GlobeLock,
  key: KeyRound,
  wrench: Wrench,
  sliders: SlidersHorizontal,
  settings: Settings,
  menu: Menu,
  sun: Sun,
  moon: Moon,
  monitor: Monitor,
  arrowRight: ArrowRight,
  arrowLeft: ArrowLeft,
  chevronDown: ChevronDown,
  chevronRight: ChevronRight,
  play: Play,
  lock: Lock,
  pin: MapPin,
  bitcoin: Bitcoin,
  mail: Mail,
  mailWarning: MailWarning,
  search: Search,
  scanSearch: ScanSearch,
  sparkle: Sparkle,
  external: ExternalLink,
  bot: Bot,
  bookOpen: BookOpen,
  history: RotateCcwClock,
  clock: Clock,
  trash: Trash,
  terminal: Terminal,
  grid: LayoutGrid,
  logOut: LogOut,
  package: Package,
  braces: Braces,
  link: Link2,
  chart: ChartNoAxesColumn,
  fingerprint: FingerprintPattern,
  gauge: Gauge,
  listChecks: ListChecks,
  route: Route,
} satisfies Record<string, LucideIcon>;

export type IconName = keyof typeof icons;

interface IconProps {
  name: IconName;
  size?: number;
  className?: string;
  /** When set, the icon is announced; otherwise it is decorative. */
  label?: string;
}

export function Icon({ name, size = 18, className, label }: IconProps) {
  const Glyph = icons[name];
  return (
    <Glyph
      size={size}
      strokeWidth={1.75}
      className={className}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      focusable="false"
    />
  );
}
