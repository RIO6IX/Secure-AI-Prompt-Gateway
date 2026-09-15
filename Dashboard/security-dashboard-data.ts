export type RiskLevel = "Critical" | "High" | "Medium" | "Low";

export const metricCards = [
  {
    label: "Prompts Inspected",
    value: "12,842",
    delta: "+18.6%",
    tone: "blue",
    description: "requests routed through the gateway",
  },
  {
    label: "Blocked Prompts",
    value: "1,245",
    delta: "+22.4%",
    tone: "red",
    description: "stopped before external AI delivery",
  },
  {
    label: "High Risk Events",
    value: "312",
    delta: "+15.3%",
    tone: "amber",
    description: "critical policy or leakage matches",
  },
  {
    label: "Sensitive Detections",
    value: "2,153",
    delta: "+20.7%",
    tone: "violet",
    description: "PII, secrets, code, and financial data",
  },
  {
    label: "Active Users",
    value: "256",
    delta: "+8.2%",
    tone: "green",
    description: "employees monitored in the last 24h",
  },
];

export const trendDays = ["Jul 22", "Jul 23", "Jul 24", "Jul 25", "Jul 26", "Jul 27", "Jul 28"];

export const trendSeries = [
  { label: "PII", color: "blue", values: [260, 355, 392, 462, 408, 356, 421] },
  { label: "Credentials", color: "red", values: [82, 132, 159, 229, 176, 188, 183] },
  { label: "Financial (PCI)", color: "amber", values: [38, 64, 82, 116, 83, 90, 87] },
  { label: "Source Code / IP", color: "violet", values: [148, 218, 272, 351, 297, 260, 289] },
];

export const categoryBreakdown = [
  { name: "PII", value: 3689, percent: 42.2, color: "#2f7df6" },
  { name: "Credentials & Secrets", value: 2317, percent: 26.5, color: "#ef3748" },
  { name: "Financial (PCI)", value: 1209, percent: 13.8, color: "#f7a717" },
  { name: "Source Code / IP", value: 1527, percent: 17.5, color: "#8557e8" },
];

export const riskDistribution = [
  { name: "High Risk", value: 1245, percent: 9.7, color: "#ef3748" },
  { name: "Medium Risk", value: 3412, percent: 26.6, color: "#f7a717" },
  { name: "Low Risk", value: 8185, percent: 63.7, color: "#35b86b" },
];

export const highRiskAlerts: Array<{
  title: string;
  user: string;
  service: string;
  time: string;
  level: RiskLevel;
}> = [
  {
    title: "API key detected in prompt",
    user: "john.doe@company.com",
    service: "ChatGPT",
    time: "2 min ago",
    level: "High",
  },
  {
    title: "Credit card number detected",
    user: "finance.team@company.com",
    service: "Gemini",
    time: "15 min ago",
    level: "High",
  },
  {
    title: "Customer PII detected",
    user: "sarah.j@company.com",
    service: "Copilot",
    time: "32 min ago",
    level: "Medium",
  },
  {
    title: "Source code block detected",
    user: "dev.team@company.com",
    service: "ChatGPT",
    time: "1 hr ago",
    level: "Medium",
  },
  {
    title: "AWS secret key detected",
    user: "admin@company.com",
    service: "Claude",
    time: "2 hr ago",
    level: "High",
  },
];

export const dataTypes = [
  { name: "Email Address", value: 1824 },
  { name: "API Keys", value: 1456 },
  { name: "Credit Card Number", value: 1209 },
  { name: "Phone Number", value: 386 },
  { name: "AWS Access Key", value: 742 },
  { name: "Source Repository URL", value: 611 },
];

export const topUsers = [
  { name: "john.doe@company.com", blocked: 142, department: "Engineering" },
  { name: "dev.team@company.com", blocked: 98, department: "Platform" },
  { name: "finance.team@company.com", blocked: 87, department: "Finance" },
  { name: "sarah.j@company.com", blocked: 65, department: "Support" },
  { name: "marketing@company.com", blocked: 48, department: "Marketing" },
];

export const auditEvents = [
  {
    id: "AUD-78421",
    timestamp: "2026-07-28 22:04:18",
    actor: "john.doe@company.com",
    action: "Prompt blocked",
    target: "ChatGPT Enterprise",
    finding: "API key",
    sanitized: "sk-proj-********************************",
    risk: "High" as RiskLevel,
    status: "Blocked",
  },
  {
    id: "AUD-78420",
    timestamp: "2026-07-28 21:57:44",
    actor: "finance.team@company.com",
    action: "Prompt sanitized",
    target: "Google Gemini",
    finding: "Credit card number",
    sanitized: "4111-****-****-1111",
    risk: "High" as RiskLevel,
    status: "Sanitized",
  },
  {
    id: "AUD-78419",
    timestamp: "2026-07-28 21:43:09",
    actor: "sarah.j@company.com",
    action: "Policy warning",
    target: "Microsoft Copilot",
    finding: "Customer email and phone",
    sanitized: "customer: ****@company.com, phone: **********",
    risk: "Medium" as RiskLevel,
    status: "Allowed with warning",
  },
  {
    id: "AUD-78418",
    timestamp: "2026-07-28 21:12:51",
    actor: "dev.team@company.com",
    action: "Source code masked",
    target: "ChatGPT Enterprise",
    finding: "Private repository snippet",
    sanitized: "function connect() { /* **** masked source **** */ }",
    risk: "Medium" as RiskLevel,
    status: "Sanitized",
  },
  {
    id: "AUD-78417",
    timestamp: "2026-07-28 20:58:23",
    actor: "admin@company.com",
    action: "Prompt blocked",
    target: "Claude",
    finding: "AWS secret key",
    sanitized: "AKIA****************",
    risk: "Critical" as RiskLevel,
    status: "Blocked",
  },
];

export const policyRules = [
  { name: "Block credentials and tokens", mode: "Enforce", hits: 791, owner: "Security" },
  { name: "Mask PCI data before AI submission", mode: "Enforce", hits: 438, owner: "Compliance" },
  { name: "Warn on source code or internal URLs", mode: "Monitor", hits: 611, owner: "Engineering" },
  { name: "Restrict finance prompts to approved services", mode: "Enforce", hits: 187, owner: "Finance" },
];

export const systemHealth = [
  { name: "Detection Engine", value: 42, state: "Normal" },
  { name: "Sanitization Engine", value: 37, state: "Normal" },
  { name: "Policy Engine", value: 29, state: "Normal" },
  { name: "Audit Pipeline", value: 16, state: "Healthy" },
];
