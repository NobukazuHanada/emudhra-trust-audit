use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub status: String,
    pub severity: String,
    pub confidence: String,
    pub action: String,
    pub evidence: Vec<Value>,
    pub remediation: Vec<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub locations: Vec<String>,
}
impl Finding {
    pub fn new(id: &str, title: &str, status: &str, action: &str) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            status: status.into(),
            severity: if action == "action_required" {
                "high"
            } else if action == "review_required" {
                "medium"
            } else {
                "info"
            }
            .into(),
            confidence: "high".into(),
            action: action.into(),
            evidence: vec![],
            remediation: vec![],
            references: vec![],
            tags: vec![],
            locations: vec![],
        }
    }
    pub fn gap(id: &str, reason: &str) -> Self {
        let mut f = Self::new(id, reason, "unable_to_assess", "review_required");
        f.remediation.push(
            "Review this coverage gap using trusted vendor tools; do not interpret it as a pass."
                .into(),
        );
        f
    }
    pub fn evidence(mut self, what: &str, value: &str) -> Self {
        self.evidence.push(json!({"what":what,"value":value}));
        self
    }
    pub fn at(mut self, location: &str) -> Self {
        self.locations.push(location.into());
        self
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: String,
    pub tool_version: String,
    pub scope: String,
    pub verdict: String,
    pub action: String,
    pub exit_code: u8,
    pub findings: Vec<Finding>,
    pub data_sources: Vec<Value>,
    pub notes: Vec<String>,
    pub errors: Vec<String>,
}
impl Report {
    pub fn new(scope: &str) -> Self {
        Self {schema_version:1,tool:"emudhra-trust-audit".into(),tool_version:env!("CARGO_PKG_VERSION").into(),scope:scope.into(),verdict:"UNKNOWN".into(),action:"review_required".into(),exit_code:1,findings:vec![],data_sources:vec![],notes:vec!["Presence is not effective acceptance; absence is not proof of safety. No malware diagnosis is made.".into()],errors:vec![]}
    }
    pub fn finish(&mut self) {
        self.action = if self.findings.iter().any(|f| f.action == "action_required") {
            "action_required"
        } else if self.findings.iter().any(|f| f.action == "review_required") {
            "review_required"
        } else {
            "none"
        }
        .into();
        self.exit_code = if !self.errors.is_empty() {
            3
        } else if self.action == "action_required" {
            2
        } else if self.action == "review_required" {
            1
        } else {
            0
        };
        self.verdict = if self
            .findings
            .iter()
            .any(|f| f.tags.iter().any(|t| t == "tls-verification-disabled"))
        {
            "INSECURE"
        } else if !self.errors.is_empty()
            || self.findings.is_empty()
            || self.findings.iter().any(|f| {
                f.status == "unable_to_assess"
                    || f.tags
                        .iter()
                        .any(|t| t == "compromised-spki-present" || t == "outdated-trust-component")
            })
        {
            "UNKNOWN"
        } else {
            "NOT_DETECTED"
        }
        .into();
    }
    pub fn sarif(&self) -> Value {
        json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":self.tool,"version":self.tool_version}},"results":self.findings.iter().map(|f|json!({"ruleId":f.id,"level":if f.action=="action_required" {"error"} else if f.action=="review_required" {"warning"} else {"note"},"message":{"text":f.title},"properties":{"status":f.status,"confidence":f.confidence,"evidence":f.evidence,"locations":f.locations,"remediation":f.remediation}})).collect::<Vec<_>>(),"properties":{"verdict":self.verdict,"exit_code":self.exit_code,"errors":self.errors}}]})
    }
}
