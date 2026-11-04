import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  BadgeCheck,
  Bell,
  ChevronDown,
  CircleHelp,
  ClipboardCheck,
  Database,
  Eye,
  EyeOff,
  FileSearch,
  Fingerprint,
  Gauge,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Search,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Pie,
  PieChart,
  ResponsiveContainer,
  Cell,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Analytics, api, Incident, Policy, ScanResult, Token } from "./api";

type Page = "overview" | "scanner" | "incidents" | "policies";
type DataBundle = { analytics: Analytics; incidents: Incident[]; policies: Policy[] };

const emptyAnalytics: Analytics = {
  total_scans: 0,
  incidents: 0,
  blocked: 0,
  masked: 0,
  reviewed: 0,
  high_risk: 0,
  average_risk: 0,
  trends: [],
  category_counts: {},
};

const navItems: { id: Page; label: string; icon: typeof LayoutDashboard }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "scanner", label: "Sample scanner", icon: FileSearch },
  { id: "incidents", label: "Incidents", icon: AlertTriangle },
  { id: "policies", label: "Policies", icon: SlidersHorizontal },
];

const categoryLabels: Record<string, string> = {
  student_name: "Student names",
  student_id: "Student IDs",
  academic_record: "Academic results",
  api_secret: "API secrets",
  pan_like_id: "PAN-like IDs",
  aadhaar_like_id: "Aadhaar-like IDs",
  account_number: "Account-like numbers",
  email: "Email addresses",
  phone: "Phone numbers",
};

function App() {
  const [token, setToken] = useState<Token | null>(() => {
    const saved = localStorage.getItem("datashield.session");
    return saved ? (JSON.parse(saved) as Token) : null;
  });
  const [page, setPage] = useState<Page>("overview");
  const [data, setData] = useState<DataBundle>({
    analytics: emptyAnalytics,
    incidents: [],
    policies: [],
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [authPage, setAuthPage] = useState<"login" | "register">(
    () => window.location.pathname === "/register" ? "register" : "login",
  );

  const signOut = useCallback(() => {
    localStorage.removeItem("datashield.session");
    setToken(null);
    setData({ analytics: emptyAnalytics, incidents: [], policies: [] });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const [analytics, incidents, policies] = await Promise.all([
        api<Analytics>("/analytics", token.access_token),
        api<Incident[]>("/incidents", token.access_token),
        api<Policy[]>("/policies", token.access_token),
      ]);
      setData({ analytics, incidents, policies });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Could not load data.";
      if (message.includes("Sign in") || message.includes("token")) signOut();
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [signOut, token]);

  useEffect(() => {
    if (token) void refresh();
  }, [refresh, token]);

  useEffect(() => {
    const syncAuthPage = () => {
      setAuthPage(window.location.pathname === "/register" ? "register" : "login");
    };
    window.addEventListener("popstate", syncAuthPage);
    return () => window.removeEventListener("popstate", syncAuthPage);
  }, []);

  const navigateAuth = useCallback((page: "login" | "register") => {
    window.history.pushState(null, "", page === "register" ? "/register" : "/");
    setAuthPage(page);
  }, []);

  if (!token) {
    return (
      authPage === "register" ? (
        <Register onBack={() => navigateAuth("login")} />
      ) : (
        <Login
          onLogin={(session) => {
            localStorage.setItem("datashield.session", JSON.stringify(session));
            setToken(session);
          }}
          onRegister={() => navigateAuth("register")}
        />
      )
    );
  }

  const availableNavItems = token.role === "viewer"
    ? navItems.filter((item) => item.id !== "scanner")
    : navItems;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img className="brand-logo" src="/privexai-logo.png" alt="PRIVEXAI" />
          <div>
            <div className="brand-name">PRIVEXAI</div>
            <div className="brand-sub">SECURITY CONSOLE</div>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <button className="workspace-switch">
          <span className="workspace-avatar"><Fingerprint size={16} /></span>
          <span className="workspace-text"><b>Demo Workspace</b><small>Sample environment</small></span>
          <ChevronDown size={15} />
        </button>

        <div className="nav-label">PLATFORM</div>
        <nav className="nav-list" aria-label="Main navigation">
          {availableNavItems.map(({ id, label, icon: Icon }) => (
            <button
              className={`nav-item ${page === id ? "active" : ""}`}
              key={id}
              onClick={() => setPage(id)}
            >
              <Icon size={17} />
              <span>{label}</span>
              {id === "incidents" && data.analytics.incidents > 0 && (
                <span className="nav-count">{data.analytics.incidents}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="environment-card">
            <span className="status-dot" />
            <div><b>Demo environment</b><small>Sample-based analysis only</small></div>
          </div>
          <div className="account-row">
            <div className="user-avatar">{token.username.slice(0, 1).toUpperCase()}</div>
            <div className="user-label"><b>{token.username}</b><small>{token.role}</small></div>
            <button className="icon-button" aria-label="Sign out" onClick={signOut}><LogOut size={16} /></button>
          </div>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-divider">/</span><b>{availableNavItems.find((item) => item.id === page)?.label}</b></div>
          <div className="topbar-actions">
            <span className="demo-pill"><span className="status-dot" /> DEMO MODE</span>
            <button className="icon-button" aria-label="Help"><CircleHelp size={18} /></button>
            <button className="icon-button notification-button" aria-label="Notifications"><Bell size={18} /><i /></button>
            <div className="top-avatar">{token.username.slice(0, 1).toUpperCase()}</div>
          </div>
        </header>

        <div className="page-content">
          {error && <div className="error-banner" role="alert"><AlertTriangle size={17} />{error}<button onClick={() => void refresh()}>Retry</button></div>}
          {page === "overview" && <Overview analytics={data.analytics} incidents={data.incidents} loading={loading} onNavigate={setPage} />}
          {page === "scanner" && <Scanner token={token.access_token} onComplete={refresh} />}
          {page === "incidents" && <Incidents incidents={data.incidents} token={token.access_token} onUpdate={refresh} />}
          {page === "policies" && <Policies policies={data.policies} token={token.access_token} onUpdate={refresh} role={token.role} />}
        </div>
        <footer className="page-footer"><span>PRIVEXAI <span className="footer-version">v0.1.0</span></span><span>Sample analysis only · No live network monitoring or external integrations</span></footer>
      </main>
    </div>
  );
}

function Login({ onLogin, onRegister }: { onLogin: (token: Token) => void; onRegister: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const session = await api<Token>("/auth/login", undefined, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      onLogin(session);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <div className="login-glow" />
      <section className="login-card">
        <div className="brand login-brand"><img className="brand-logo" src="/privexai-logo.png" alt="PRIVEXAI" /><div><div className="brand-name">PRIVEXAI</div><div className="brand-sub">SECURITY CONSOLE</div></div></div>
        <div className="login-kicker"><span className="status-dot" /> SECURE WORKSPACE</div>
        <h1>Protect what<br />matters most.</h1>
        <p>Sign in to analyze submitted samples and review security events.</p>
        <form onSubmit={submit} className="login-form">
          <label htmlFor="username">Email or username</label>
          <input id="username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required />
          <label htmlFor="password">Password</label>
          <div className="password-input"><input id="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /><button type="button" className="password-toggle" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((visible) => !visible)}>{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button></div>
          {error && <div className="form-error" role="alert">{error}</div>}
          <button className="primary-button login-submit" disabled={busy}>{busy ? "Signing in..." : "Sign in"}<ArrowUpRight size={17} /></button>
        </form>
        <div className="auth-switch">New to PRIVEXAI? <button type="button" onClick={onRegister}>Create an account</button></div>
        <div className="login-note"><LockKeyhole size={14} /> Passwords are securely hashed. Public accounts start as viewers.</div>
      </section>
      <div className="login-caption">INTELLIGENT DATA PROTECTION <span>·</span> SAMPLE-BASED DEMO</div>
    </div>
  );
}

function Register({ onBack }: { onBack: () => void }) {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const session = await api<Token>("/auth/register", undefined, {
        method: "POST",
        body: JSON.stringify({ full_name: fullName, email, username, password }),
      });
      setUsername(session.username);
      setCreated(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Account creation failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen registration-screen">
      <div className="login-glow" />
      <section className="login-card register-card">
        <div className="brand login-brand"><img className="brand-logo" src="/privexai-logo.png" alt="PRIVEXAI" /><div><div className="brand-name">PRIVEXAI</div><div className="brand-sub">SECURITY CONSOLE</div></div></div>
        {created ? (
          <>
            <div className="login-kicker"><span className="status-dot" /> ACCOUNT CREATED</div>
            <h1>You’re all<br />set.</h1>
            <p role="status">Account <b>{username}</b> is ready with viewer access. Sign in using your username or email address.</p>
            <button type="button" className="primary-button login-submit" onClick={onBack}>Go to sign in<ArrowUpRight size={17} /></button>
            <div className="login-note"><LockKeyhole size={14} /> Your account cannot scan samples or change policies.</div>
          </>
        ) : (
          <>
        <div className="login-kicker"><span className="status-dot" /> CREATE A SECURE ACCOUNT</div>
        <h1>Join your<br />workspace.</h1>
        <p>Self-service accounts receive viewer access. An administrator can grant additional permissions.</p>
        <form onSubmit={submit} className="login-form">
          <label htmlFor="full-name">Full name</label>
          <input id="full-name" autoComplete="name" value={fullName} onChange={(event) => setFullName(event.target.value)} minLength={2} maxLength={120} required />
          <label htmlFor="register-email">Email</label>
          <input id="register-email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} maxLength={254} required />
          <label htmlFor="register-username">Username</label>
          <input id="register-username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} minLength={3} maxLength={80} required />
          <label htmlFor="register-password">Password</label>
          <input id="register-password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={12} maxLength={256} required />
          <label htmlFor="confirm-password">Confirm password</label>
          <input id="confirm-password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} minLength={12} maxLength={256} required />
          <div className="password-hint">Use at least 12 characters with uppercase, lowercase, a number, and a symbol.</div>
          {error && <div className="form-error" role="alert">{error}</div>}
          <button className="primary-button login-submit" disabled={busy}>{busy ? "Creating account..." : "Create viewer account"}<ArrowUpRight size={17} /></button>
        </form>
        <div className="auth-switch">Already registered? <button type="button" onClick={onBack}>Sign in</button></div>
        <div className="login-note"><LockKeyhole size={14} /> Email verification and password recovery are not configured in this demo.</div>
          </>
        )}
      </section>
      <div className="login-caption">INTELLIGENT DATA PROTECTION <span>·</span> SAMPLE-BASED DEMO</div>
    </div>
  );
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return (
    <div className="page-heading">
      <div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>
      {action}
    </div>
  );
}

function Overview({ analytics, incidents, loading, onNavigate }: { analytics: Analytics; incidents: Incident[]; loading: boolean; onNavigate: (page: Page) => void }) {
  const chartData = analytics.trends.map((point) => ({
    ...point,
    label: new Date(`${point.date}T12:00:00`).toLocaleDateString("en", { weekday: "short" }),
  }));
  const categoryData = Object.entries(analytics.category_counts).map(([name, value]) => ({
    name: categoryLabels[name] ?? name,
    value,
  }));
  const colors = ["#54e1b5", "#7994ff", "#ffba62", "#ba8cff", "#55c8e8", "#ff7486"];
  const statCards = [
    { label: "SAMPLES ANALYZED", value: analytics.total_scans, change: "Submitted samples", icon: Activity, tone: "mint" },
    { label: "NEEDS REVIEW", value: analytics.reviewed, change: "Manual decision queue", icon: CircleHelp, tone: "purple" },
    { label: "TRANSFERS BLOCKED", value: analytics.blocked, change: "Policy enforcement", icon: ShieldAlert, tone: "red" },
    { label: "RISK SCORE AVG.", value: `${analytics.average_risk}/100`, change: "Across demo events", icon: Gauge, tone: "amber" },
  ];

  return (
    <>
      <PageHeading eyebrow="SECURITY OVERVIEW" title="Good morning, team" description="A clear view of sensitive data exposure across your submitted samples." action={<button className="secondary-button" onClick={() => onNavigate("scanner")}><FileSearch size={16} /> Analyze a sample</button>} />
      <div className="info-strip"><Sparkles size={16} /><span><b>Demo workspace</b> — metrics below include synthetic demonstration events and samples you submit. No traffic is monitored.</span><button aria-label="Dismiss information"><X size={15} /></button></div>
      <div className="stat-grid">
        {statCards.map(({ label, value, change, icon: Icon, tone }) => (
          <article className="stat-card" key={label}>
            <div className="stat-top"><span>{label}</span><span className={`stat-icon ${tone}`}><Icon size={17} /></span></div>
            <div className="stat-value">{loading ? "—" : value}</div>
            <div className="stat-caption"><span className={`trend-mark ${tone}`}><ArrowUpRight size={13} /></span>{change}</div>
          </article>
        ))}
      </div>

      <div className="dashboard-grid">
        <section className="panel trend-panel">
          <div className="panel-heading"><div><h2>Risk activity</h2><p>Submitted sample decisions · last 7 days</p></div><button className="period-button">7 days <ChevronDown size={14} /></button></div>
          <div className="chart-legend"><span><i className="legend-dot mint-dot" /> Sample scans</span><span><i className="legend-dot red-dot" /> Blocked</span></div>
          <div className="trend-chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 4, left: -20, bottom: 0 }}>
                <defs><linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#54e1b5" stopOpacity={0.22} /><stop offset="95%" stopColor="#54e1b5" stopOpacity={0} /></linearGradient></defs>
                <CartesianGrid stroke="#1d2a3a" vertical={false} />
                <XAxis dataKey="label" axisLine={false} tickLine={false} tick={{ fill: "#718197", fontSize: 11 }} dy={10} />
                <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#718197", fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#111a27", border: "1px solid #263648", borderRadius: 9, color: "#eaf1f7" }} />
                <Area type="monotone" dataKey="scans" name="Samples" stroke="#54e1b5" strokeWidth={2.5} fill="url(#scanFill)" />
                <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ff7486" strokeWidth={2} fill="transparent" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>
        <section className="panel category-panel">
          <div className="panel-heading"><div><h2>Data types detected</h2><p>Across flagged sample events</p></div><button className="more-button" aria-label="More information"><CircleHelp size={17} /></button></div>
          <div className="category-chart">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart><Pie data={categoryData} dataKey="value" nameKey="name" innerRadius={54} outerRadius={76} paddingAngle={4} stroke="none">{categoryData.map((_, index) => <Cell key={index} fill={colors[index % colors.length]} />)}</Pie><Tooltip contentStyle={{ background: "#111a27", border: "1px solid #263648", borderRadius: 9, color: "#eaf1f7" }} /></PieChart>
            </ResponsiveContainer>
            {categoryData.length === 0 && <div className="empty-chart">No findings yet</div>}
          </div>
          <div className="category-legend">{categoryData.slice(0, 4).map((item, index) => <div key={item.name}><span><i style={{ background: colors[index % colors.length] }} />{item.name}</span><b>{item.value}</b></div>)}</div>
        </section>
      </div>

      <section className="panel incidents-panel">
        <div className="panel-heading"><div><h2>Recent incidents</h2><p>Latest sensitive-data findings from sample analysis</p></div><button className="text-button" onClick={() => onNavigate("incidents")}>View all <ArrowUpRight size={15} /></button></div>
        <IncidentTable incidents={incidents.slice(0, 5)} />
      </section>

      <div className="bottom-grid">
        <button className="action-card" onClick={() => onNavigate("scanner")}><span className="action-icon mint"><Search size={18} /></span><span><b>Analyze a sample</b><small>Check submitted text for sensitive values</small></span><ArrowUpRight size={17} /></button>
        <button className="action-card" onClick={() => onNavigate("policies")}><span className="action-icon purple"><ClipboardCheck size={18} /></span><span><b>Review policies</b><small>Manage category actions and risk weights</small></span><ArrowUpRight size={17} /></button>
        <div className="protection-note"><ShieldCheck size={18} /><span><b>Protection active</b><small>Risk-aware rules apply to sample submissions</small></span><BadgeCheck size={16} /></div>
      </div>
    </>
  );
}

function Scanner({ token, onComplete }: { token: string; onComplete: () => void | Promise<void> }) {
  const [text, setText] = useState("Student name: Jamie Rivera\nEmail: jamie.rivera@example.test\nPhone: 9876543210\nStudent ID: STU-2048\nGPA: 3.8\nAcademic note: Synthetic demo record only.");
  const [source, setSource] = useState("Student Demo Workspace");
  const [destination, setDestination] = useState("External partner");
  const [authorized, setAuthorized] = useState(false);
  const [context, setContext] = useState<"internal" | "partner" | "public">("partner");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await api<ScanResult>("/scans", token, {
        method: "POST",
        body: JSON.stringify({
          text,
          source,
          destination,
          destination_authorized: authorized,
          context,
        }),
      });
      setResult(response);
      await onComplete();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sample could not be analyzed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeading eyebrow="SAMPLE INSPECTION" title="Analyze a sample" description="Submit text for sensitive-data analysis. This tool does not inspect network traffic." />
      <div className="scanner-layout">
        <form className="panel scan-form" onSubmit={submit}>
          <div className="form-section-title"><span className="step-badge">01</span><div><h2>Sample content</h2><p>Enter synthetic or authorized text for inspection.</p></div></div>
          <label className="field-label" htmlFor="sample-text">Text to analyze</label>
          <textarea id="sample-text" value={text} onChange={(event) => setText(event.target.value)} maxLength={20000} required placeholder="Paste text to inspect..." />
          <div className="char-count">{text.length.toLocaleString()} / 20,000 characters</div>
          <div className="form-row">
            <div><label className="field-label" htmlFor="sample-source">Source</label><input id="sample-source" value={source} onChange={(event) => setSource(event.target.value)} maxLength={120} required /></div>
            <div><label className="field-label" htmlFor="sample-destination">Destination</label><input id="sample-destination" value={destination} onChange={(event) => setDestination(event.target.value)} maxLength={160} required /></div>
          </div>
          <div className="form-row">
            <div><label className="field-label" htmlFor="sample-context">Sharing context</label><select id="sample-context" value={context} onChange={(event) => setContext(event.target.value as typeof context)}><option value="internal">Internal</option><option value="partner">External partner</option><option value="public">Public</option></select></div>
            <label className="check-field"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span><b>Authorized destination</b><small>Apply a lower destination risk factor</small></span></label>
          </div>
          {error && <div className="form-error" role="alert">{error}</div>}
          <div className="scan-actions"><span><LockKeyhole size={14} /> Raw sample text is not retained.</span><button className="primary-button" disabled={busy || !text.trim()}>{busy ? "Analyzing..." : "Analyze sample"}<Send size={15} /></button></div>
        </form>

        <section className="panel result-panel">
          <div className="panel-heading"><div><h2>Analysis result</h2><p>Decision and explainable risk factors</p></div><span className="result-shield"><Shield size={18} /></span></div>
          {!result ? <div className="result-empty"><div className="result-empty-icon"><FileSearch size={25} /></div><b>Ready when you are</b><p>Submit sample text to see findings, policy action and risk score.</p><div className="result-empty-note"><Database size={14} /> No network traffic is monitored</div></div> : (
            <div className="result-content">
              <div className={`decision-banner ${result.decision}`}><div className="decision-icon">{result.decision === "block" ? <ShieldAlert size={20} /> : result.decision === "mask" ? <Fingerprint size={20} /> : result.decision === "review" ? <CircleHelp size={20} /> : <ShieldCheck size={20} />}</div><div><small>POLICY DECISION</small><b>{result.decision.toUpperCase()}</b></div><div className="score-pill">{result.risk_score}<small>/100</small></div></div>
              <p className="result-message">{result.message}</p>
              <div className="result-section-label">DETECTED DATA <span>{result.findings.reduce((sum, item) => sum + item.count, 0)}</span></div>
              {result.findings.length ? <div className="finding-list">{result.findings.map((item) => <div className="finding-row" key={item.category}><span className="finding-dot" /><span>{categoryLabels[item.category] ?? item.category}</span><b>{item.count}</b></div>)}</div> : <div className="no-findings"><BadgeCheck size={17} /> No configured sensitive-data patterns detected</div>}
              <div className="result-section-label">RISK FACTORS</div>
              <div className="risk-factor-list">{result.risk_factors.map((factor, index) => <div className="risk-factor" key={`${factor.label}-${index}`}><span>{factor.label}</span><b className={factor.points < 0 ? "negative" : ""}>{factor.points > 0 ? "+" : ""}{factor.points}</b></div>)}</div>
              <div className="recommendation"><BadgeCheck size={14} /><span><b>RECOMMENDED ACTION</b><small>{result.recommended_action}</small></span></div>
              <div className="protected-sample"><div><span>PROTECTED PREVIEW</span><LockKeyhole size={13} /></div><p>{result.protected_preview}</p></div>
            </div>
          )}
        </section>
      </div>
      <div className="scanner-disclaimer"><AlertTriangle size={15} /><span>Detection uses configurable pattern and context rules. Validate policies against your organization’s requirements before production use.</span></div>
    </>
  );
}

function Incidents({ incidents, token, onUpdate }: { incidents: Incident[]; token: string; onUpdate: () => void | Promise<void> }) {
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState("");
  const filtered = useMemo(() => filter === "all" ? incidents : incidents.filter((incident) => incident.decision === filter), [filter, incidents]);

  async function updateStatus(incidentId: number, status: string) {
    setError("");
    try {
      await api<Incident>(`/incidents/${incidentId}`, token, { method: "PATCH", body: JSON.stringify({ status }) });
      await onUpdate();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Status update failed.");
    }
  }

  return (
    <>
      <PageHeading eyebrow="SECURITY EVENTS" title="Incidents" description="Review findings from submitted samples and track remediation status." action={<span className="count-badge"><Activity size={14} /> {incidents.length} events</span>} />
      {error && <div className="error-banner" role="alert"><AlertTriangle size={16} />{error}</div>}
      <section className="panel incidents-panel full-table-panel">
        <div className="table-toolbar"><div className="filter-tabs">{["all", "block", "mask", "review", "allow"].map((item) => <button key={item} className={filter === item ? "selected" : ""} onClick={() => setFilter(item)}>{item === "all" ? "All events" : item[0].toUpperCase() + item.slice(1)}</button>)}</div><button className="secondary-button small-button"><SlidersHorizontal size={15} /> Filters</button></div>
        <IncidentTable incidents={filtered} onStatusChange={updateStatus} />
      </section>
      <p className="table-note"><LockKeyhole size={13} /> Incident records store masked previews and finding metadata, not submitted raw sample text.</p>
    </>
  );
}

function IncidentTable({ incidents, onStatusChange }: { incidents: Incident[]; onStatusChange?: (id: number, status: string) => void }) {
  if (!incidents.length) return <div className="table-empty"><ShieldCheck size={20} /><b>No incidents to show</b><span>Submitted sample findings will appear here.</span></div>;
  return (
    <div className="table-scroll"><table className="data-table"><thead><tr><th>EVENT</th><th>SOURCE → DESTINATION</th><th>DATA TYPES</th><th>RISK</th><th>DECISION</th><th>RECOMMENDED ACTION</th><th>STATUS</th><th>TIME</th></tr></thead><tbody>
      {incidents.map((incident) => (
        <tr key={incident.id}>
          <td><div className="event-id">DS-{String(incident.id).padStart(4, "0")}</div><div className="event-sub">Sample inspection</div></td>
          <td><div className="route-cell"><b>{incident.source}</b><span><ArrowDownRight size={12} />{incident.destination}</span></div></td>
          <td><div className="tag-list">{incident.categories.length ? incident.categories.slice(0, 2).map((category) => <span className="data-tag" key={category}>{categoryLabels[category] ?? category}</span>) : <span className="event-sub">No findings</span>}{incident.categories.length > 2 && <span className="data-tag">+{incident.categories.length - 2}</span>}</div></td>
          <td><div className="risk-cell"><div className="risk-meter"><i style={{ width: `${incident.risk_score}%` }} className={incident.severity} /></div><b>{incident.risk_score}</b></div><div className={`severity-label ${incident.severity}`}>{incident.severity}</div></td>
          <td><span className={`decision-tag ${incident.decision}`}><i />{incident.decision}</span></td>
          <td className="recommended-cell">{incident.recommended_action}</td>
          <td>{onStatusChange ? <select className="status-select" value={incident.status} onChange={(event) => void onStatusChange(incident.id, event.target.value)} aria-label={`Status for incident ${incident.id}`}><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select> : <span className={`status-tag ${incident.status}`}>{incident.status}</span>}</td>
          <td className="time-cell">{new Date(incident.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
        </tr>
      ))}
    </tbody></table></div>
  );
}

function Policies({ policies, token, onUpdate, role }: { policies: Policy[]; token: string; onUpdate: () => void | Promise<void>; role: string }) {
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [draftWeights, setDraftWeights] = useState<Record<string, number>>({});

  async function savePolicy(policy: Policy, values: Partial<Policy>) {
    setError("");
    setSaved("");
    try {
      await api<Policy>(`/policies/${policy.category}`, token, {
        method: "PUT",
        body: JSON.stringify({
          action: values.action ?? policy.action,
          weight: values.weight ?? policy.weight,
          enabled: values.enabled ?? policy.enabled,
        }),
      });
      if (values.weight !== undefined) {
        setDraftWeights((current) => ({ ...current, [policy.category]: values.weight! }));
      }
      setSaved(policy.category);
      await onUpdate();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Policy could not be updated.");
    }
  }

  return (
    <>
      <PageHeading eyebrow="POLICY MANAGEMENT" title="Security policies" description="Configure how detected categories affect risk and sample-transfer decisions." action={<span className="count-badge"><LockKeyhole size={14} /> {role === "admin" ? "Administrator" : "Read only"}</span>} />
      <div className="info-strip"><Sparkles size={16} /><span>Rules apply only when a user submits sample text. Validate all policy weights and actions before production adoption.</span></div>
      {error && <div className="error-banner" role="alert"><AlertTriangle size={16} />{error}</div>}
      <section className="panel policies-panel">
        <div className="panel-heading"><div><h2>Detection rules</h2><p>Action and base risk weight per sensitive-data category</p></div><span className="policy-status"><span className="status-dot" /> {policies.filter((policy) => policy.enabled).length} active</span></div>
        <div className="policy-list">{policies.map((policy) => <article className={`policy-row ${!policy.enabled ? "disabled" : ""}`} key={policy.category}>
          <div className={`policy-type-icon ${policy.action}`}><Fingerprint size={17} /></div>
          <div className="policy-name"><b>{categoryLabels[policy.category] ?? policy.category}</b><small>{policy.description}</small></div>
          <div className="policy-weight"><span>RISK WEIGHT</span><b>{draftWeights[policy.category] ?? policy.weight}<small> pts</small></b>{role === "admin" && <input type="range" min="0" max="100" value={draftWeights[policy.category] ?? policy.weight} aria-label={`Risk weight for ${policy.category}`} onChange={(event) => setDraftWeights((current) => ({ ...current, [policy.category]: Number(event.target.value) }))} />}</div>
          <div className="policy-controls">
            {role === "admin" ? <>
              <select value={policy.action} aria-label={`Action for ${policy.category}`} onChange={(event) => void savePolicy(policy, { action: event.target.value as Policy["action"] })}><option value="mask">Mask</option><option value="block">Block</option></select>
              <button className={`toggle ${policy.enabled ? "on" : ""}`} aria-label={`${policy.enabled ? "Disable" : "Enable"} ${policy.category}`} onClick={() => void savePolicy(policy, { enabled: !policy.enabled })}><i /></button>
              {draftWeights[policy.category] !== undefined && draftWeights[policy.category] !== policy.weight && <button className="save-policy-button" onClick={() => void savePolicy(policy, { weight: draftWeights[policy.category] })}>Save</button>}
            </> : <span className={`decision-tag ${policy.action}`}><i />{policy.action}</span>}
          </div>
          {saved === policy.category && <span className="saved-check"><BadgeCheck size={14} /> Saved</span>}
        </article>)}</div>
        {!policies.length && <div className="table-empty"><SlidersHorizontal size={20} /><b>No policies configured</b><span>Default category rules are initialized by the API.</span></div>}
      </section>
      <div className="policy-footnote"><LockKeyhole size={14} /> Only administrators can change policy actions and enablement. Changes are applied to new sample submissions.</div>
    </>
  );
}

export default App;
