//! Bounded, local-only security evaluation for the approved Task6 v0.1 rules.
//!
//! This module accepts normalized categorical evidence. It does not read files,
//! access the network, upload findings, block actions, or retain raw commands.

use serde::Serialize;

pub mod delivery_queue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorMode {
    Off,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDecision {
    Off,
    NoMatch,
    MonitorMatch,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionContext {
    ParsedCommand,
    Documentation,
    PrintedText,
    ApplicationCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserStatus {
    Complete,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellDialect {
    Posix,
    PowerShell,
    Cmd,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    FilesystemRoot,
    UserHome,
    RepositoryBuild,
    TemporaryFolder,
    Other,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetExpansion {
    Confirmed,
    Literal,
    NotApplicable,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteInput {
    pub execution_context: ExecutionContext,
    pub parser_status: ParserStatus,
    pub dialect: ShellDialect,
    pub recursive: bool,
    pub forced: bool,
    pub target_class: TargetClass,
    pub target_expansion: TargetExpansion,
}

impl DeleteInput {
    pub fn new(dialect: ShellDialect, target_class: TargetClass) -> Self {
        Self {
            execution_context: ExecutionContext::ParsedCommand,
            parser_status: ParserStatus::Complete,
            dialect,
            recursive: true,
            forced: true,
            target_class,
            target_expansion: TargetExpansion::NotApplicable,
        }
    }

    pub fn with_execution_context(mut self, execution_context: ExecutionContext) -> Self {
        self.execution_context = execution_context;
        self
    }

    pub fn with_parser_status(mut self, parser_status: ParserStatus) -> Self {
        self.parser_status = parser_status;
        self
    }

    pub fn with_target_expansion(mut self, target_expansion: TargetExpansion) -> Self {
        self.target_expansion = target_expansion;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadSource {
    Http,
    Https,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputDisposition {
    Pipeline,
    SavedFile,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpreterClass {
    Shell,
    ScriptInterpreter,
    Other,
    None,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpreterInput {
    DownloaderStdout,
    LocalFile,
    Redirected,
    CommandString,
    None,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadPipelineInput {
    pub execution_context: ExecutionContext,
    pub parser_status: ParserStatus,
    pub download_source: DownloadSource,
    pub output_disposition: OutputDisposition,
    pub interpreter_class: InterpreterClass,
    pub interpreter_input: InterpreterInput,
}

impl DownloadPipelineInput {
    pub fn new(
        download_source: DownloadSource,
        output_disposition: OutputDisposition,
        interpreter_class: InterpreterClass,
        interpreter_input: InterpreterInput,
    ) -> Self {
        Self {
            execution_context: ExecutionContext::ParsedCommand,
            parser_status: ParserStatus::Complete,
            download_source,
            output_disposition,
            interpreter_class,
            interpreter_input,
        }
    }

    pub fn with_execution_context(mut self, execution_context: ExecutionContext) -> Self {
        self.execution_context = execution_context;
        self
    }

    pub fn with_parser_status(mut self, parser_status: ParserStatus) -> Self {
        self.parser_status = parser_status;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    ConnectBack,
    Bind,
    Listener,
    NormalSocket,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportClass {
    DeviceRedirect,
    NetcatFamily,
    Socat,
    GenericSocket,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutedProgramClass {
    RecognizedShell,
    NonShell,
    None,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReverseShellInput {
    pub execution_context: ExecutionContext,
    pub parser_status: ParserStatus,
    pub network_mode: NetworkMode,
    pub transport_class: TransportClass,
    pub executed_program_class: ExecutedProgramClass,
}

impl ReverseShellInput {
    pub fn new(
        network_mode: NetworkMode,
        transport_class: TransportClass,
        executed_program_class: ExecutedProgramClass,
    ) -> Self {
        Self {
            execution_context: ExecutionContext::ParsedCommand,
            parser_status: ParserStatus::Complete,
            network_mode,
            transport_class,
            executed_program_class,
        }
    }

    pub fn with_execution_context(mut self, execution_context: ExecutionContext) -> Self {
        self.execution_context = execution_context;
        self
    }

    pub fn with_parser_status(mut self, parser_status: ParserStatus) -> Self {
        self.parser_status = parser_status;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationInput {
    Delete(DeleteInput),
    DownloadPipeline(DownloadPipelineInput),
    ReverseShell(ReverseShellInput),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeFinding {
    pub rule_id: &'static str,
    pub rule_version: &'static str,
    pub severity: &'static str,
    pub alert_title: &'static str,
    pub effect: &'static str,
    pub phase: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingOperatingSystem {
    Macos,
    Linux,
    Windows,
    Wsl,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingUploadContext {
    pub finding_id: String,
    pub delivery_id: String,
    pub repository_id: String,
    pub session_id: String,
    pub source_event_id: String,
    pub correlation_id: Option<String>,
    pub operating_system: FindingOperatingSystem,
    pub occurred_at: String,
    pub client_version: String,
    pub rule_pack_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityFindingUploadBatch {
    schema_version: &'static str,
    findings: Vec<SecurityFindingUpload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityFindingUpload {
    finding_id: String,
    delivery_id: String,
    repository_id: String,
    session_id: String,
    source_event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    correlation_id: Option<String>,
    rule: FindingUploadRule,
    capability: FindingUploadCapability,
    effect: &'static str,
    phase: &'static str,
    availability: &'static str,
    completeness: &'static str,
    result_category: &'static str,
    occurred_at: String,
    client_version: String,
    rule_pack_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FindingUploadRule {
    id: &'static str,
    version: &'static str,
    category: &'static str,
    severity: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingUploadCapability {
    route_id: &'static str,
    agent_family: &'static str,
    host_surface: &'static str,
    host_mode: &'static str,
    capture_channel: &'static str,
    operating_system: FindingOperatingSystem,
    timing: &'static str,
    native_effect: &'static str,
    activation: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingUploadProjectionError;

impl std::fmt::Display for FindingUploadProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "security finding upload metadata is invalid")
    }
}

impl std::error::Error for FindingUploadProjectionError {}

impl SecurityFindingUploadBatch {
    pub fn from_safe_finding(
        finding: SafeFinding,
        context: FindingUploadContext,
    ) -> Result<Self, FindingUploadProjectionError> {
        for value in [
            context.finding_id.as_str(),
            context.delivery_id.as_str(),
            context.repository_id.as_str(),
            context.session_id.as_str(),
            context.source_event_id.as_str(),
        ] {
            validate_bounded(value, 128)?;
        }
        if let Some(value) = context.correlation_id.as_deref() {
            validate_bounded(value, 128)?;
        }
        validate_bounded(&context.occurred_at, 64)?;
        validate_bounded(&context.client_version, 64)?;
        validate_bounded(&context.rule_pack_version, 64)?;

        Ok(Self {
            schema_version: "trackai.security-finding-upload/0.1",
            findings: vec![SecurityFindingUpload {
                finding_id: context.finding_id,
                delivery_id: context.delivery_id,
                repository_id: context.repository_id,
                session_id: context.session_id,
                source_event_id: context.source_event_id,
                correlation_id: context.correlation_id,
                rule: FindingUploadRule {
                    id: finding.rule_id,
                    version: finding.rule_version,
                    category: "execution",
                    severity: finding.severity,
                },
                capability: FindingUploadCapability {
                    route_id: "AC-CLI-03",
                    agent_family: "opencode",
                    host_surface: "terminal",
                    host_mode: "cli",
                    capture_channel: "provider-plugin",
                    operating_system: context.operating_system,
                    timing: "pre_action",
                    native_effect: "observe_only",
                    activation: "observed",
                },
                effect: finding.effect,
                phase: finding.phase,
                availability: "available",
                completeness: "complete",
                result_category: "not_observed",
                occurred_at: context.occurred_at,
                client_version: context.client_version,
                rule_pack_version: context.rule_pack_version,
            }],
        })
    }

    pub(crate) fn repository_id(&self) -> &str {
        &self.findings[0].repository_id
    }

    pub(crate) fn delivery_id(&self) -> &str {
        &self.findings[0].delivery_id
    }
}

fn validate_bounded(value: &str, maximum: usize) -> Result<(), FindingUploadProjectionError> {
    if value.is_empty() || value.len() > maximum {
        return Err(FindingUploadProjectionError);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: LocalDecision,
    pub finding: Option<SafeFinding>,
}

const MAX_COMMAND_BYTES: usize = 8192;
const MAX_COMMAND_TOKENS: usize = 256;
const MAX_PIPELINE_STAGES: usize = 32;

/// Parse and evaluate one bounded command request locally.
///
/// The command is borrowed only for this call and is never copied into the
/// returned finding. Unsupported dialects and ambiguous syntax fail closed as
/// `Unavailable`.
pub fn evaluate_command(
    mode: MonitorMode,
    dialect: ShellDialect,
    execution_context: ExecutionContext,
    command: &str,
) -> Evaluation {
    if mode == MonitorMode::Off {
        return Evaluation {
            decision: LocalDecision::Off,
            finding: None,
        };
    }
    if execution_context != ExecutionContext::ParsedCommand {
        return no_match();
    }
    if command.len() > MAX_COMMAND_BYTES || command.contains('\0') {
        return unavailable();
    }
    if matches!(dialect, ShellDialect::Cmd | ShellDialect::PowerShell) {
        return evaluate_windows_delete(mode, dialect, command);
    }
    if dialect != ShellDialect::Posix {
        return unavailable();
    }

    let Some(stages) = split_posix_pipeline(command) else {
        return unavailable();
    };
    if stages.len() > MAX_PIPELINE_STAGES {
        return unavailable();
    }

    let mut tokenized = Vec::with_capacity(stages.len());
    for stage in &stages {
        let Some(tokens) = shlex::split(stage) else {
            return unavailable();
        };
        if tokens.len() > MAX_COMMAND_TOKENS {
            return unavailable();
        }
        tokenized.push(tokens);
    }

    if tokenized.len() == 1 {
        let tokens = &tokenized[0];
        if is_destructive_root_delete(tokens) {
            return evaluate(
                mode,
                &EvaluationInput::Delete(DeleteInput::new(
                    ShellDialect::Posix,
                    TargetClass::FilesystemRoot,
                )),
            );
        }
        if let Some(input) = normalized_reverse_shell(tokens, command) {
            return evaluate(mode, &EvaluationInput::ReverseShell(input));
        }
    }

    if let Some(input) = normalized_download_pipeline(&tokenized, &stages) {
        return evaluate(mode, &EvaluationInput::DownloadPipeline(input));
    }

    no_match()
}

fn split_posix_pipeline(command: &str) -> Option<Vec<&str>> {
    let mut stages = Vec::new();
    let mut start = 0;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let bytes = command.as_bytes();

    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if !single_quoted => escaped = true,
            b'\'' if !double_quoted => single_quoted = !single_quoted,
            b'"' if !single_quoted => double_quoted = !double_quoted,
            b'|' if !single_quoted && !double_quoted => {
                if bytes.get(index + 1) == Some(&b'|') || index > 0 && bytes[index - 1] == b'|' {
                    return None;
                }
                let stage = command[start..index].trim();
                if stage.is_empty() {
                    return None;
                }
                stages.push(stage);
                start = index + 1;
            }
            b';' if !single_quoted && !double_quoted => return None,
            b'&' if !single_quoted
                && !double_quoted
                && (index == 0 || bytes[index - 1] != b'>') =>
            {
                return None;
            }
            _ => {}
        }
    }
    if escaped || single_quoted || double_quoted {
        return None;
    }

    let last = command[start..].trim();
    if last.is_empty() {
        return None;
    }
    stages.push(last);
    Some(stages)
}

fn executable_name(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

fn evaluate_windows_delete(mode: MonitorMode, dialect: ShellDialect, command: &str) -> Evaluation {
    let Some(tokens) = split_windows_words(command) else {
        return unavailable();
    };
    if tokens.len() > MAX_COMMAND_TOKENS {
        return unavailable();
    }
    let Some(executable) = tokens.first().map(|token| executable_name(token)) else {
        return no_match();
    };

    let (is_delete, recursive, forced) = match dialect {
        ShellDialect::Cmd => (
            executable.eq_ignore_ascii_case("rd") || executable.eq_ignore_ascii_case("rmdir"),
            tokens.iter().any(|token| token.eq_ignore_ascii_case("/s")),
            tokens.iter().any(|token| token.eq_ignore_ascii_case("/q")),
        ),
        ShellDialect::PowerShell => (
            executable.eq_ignore_ascii_case("remove-item"),
            tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case("-recurse")),
            tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case("-force")),
        ),
        _ => return unavailable(),
    };
    if !is_delete {
        return no_match();
    }

    let root_target = tokens
        .iter()
        .skip(1)
        .any(|token| is_windows_drive_root(token));
    if recursive && forced && root_target {
        evaluate(
            mode,
            &EvaluationInput::Delete(DeleteInput::new(dialect, TargetClass::FilesystemRoot)),
        )
    } else {
        no_match()
    }
}

fn split_windows_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in command.chars() {
        match (quote, character) {
            (Some(active), value) if value == active => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, ';' | '|' | '&') => return None,
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            (_, value) => current.push(value),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        words.push(current);
    }
    Some(words)
}

fn is_windows_drive_root(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn is_destructive_root_delete(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    if executable_name(first) != "rm" {
        return false;
    }

    let mut recursive = false;
    let mut forced = false;
    let mut root_target = false;
    let mut options_ended = false;
    for token in &tokens[1..] {
        if !options_ended && token == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && token.starts_with('-') {
            recursive |=
                token == "--recursive" || token[1..].contains('r') || token[1..].contains('R');
            forced |= token == "--force" || token[1..].contains('f');
            continue;
        }
        root_target |= token == "/";
    }
    recursive && forced && root_target
}

fn normalized_download_pipeline(
    tokenized: &[Vec<String>],
    raw_stages: &[&str],
) -> Option<DownloadPipelineInput> {
    if tokenized.len() != 2 {
        return None;
    }
    let source = &tokenized[0];
    let sink = &tokenized[1];
    let downloader = executable_name(source.first()?);
    if !matches!(downloader, "curl" | "wget") {
        return None;
    }

    let download_source = if source.iter().any(|arg| arg.starts_with("https://")) {
        DownloadSource::Https
    } else if source.iter().any(|arg| arg.starts_with("http://")) {
        DownloadSource::Http
    } else {
        return None;
    };
    if source.iter().any(|arg| {
        matches!(arg.as_str(), "-o" | "--output" | "-O" | "--output-document")
            || arg.starts_with("--output=")
            || arg.starts_with("--output-document=")
    }) {
        return None;
    }

    let interpreter = executable_name(sink.first()?);
    let interpreter_class = match interpreter {
        "sh" | "bash" | "dash" | "ksh" | "zsh" => InterpreterClass::Shell,
        "python" | "python3" | "ruby" | "perl" => InterpreterClass::ScriptInterpreter,
        _ => return None,
    };
    let args = &sink[1..];
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-c" | "--command"))
        || raw_stages[1].contains('<')
    {
        return None;
    }
    let reads_stdin = args.is_empty() || args.iter().all(|arg| arg == "-");
    if !reads_stdin {
        return None;
    }

    Some(DownloadPipelineInput::new(
        download_source,
        OutputDisposition::Pipeline,
        interpreter_class,
        InterpreterInput::DownloaderStdout,
    ))
}

fn normalized_reverse_shell(tokens: &[String], raw_command: &str) -> Option<ReverseShellInput> {
    let executable = executable_name(tokens.first()?);
    if matches!(executable, "sh" | "bash" | "dash" | "ksh" | "zsh")
        && tokens.iter().any(|arg| arg == "-i")
        && raw_command.contains("/dev/tcp/")
    {
        return Some(ReverseShellInput::new(
            NetworkMode::ConnectBack,
            TransportClass::DeviceRedirect,
            ExecutedProgramClass::RecognizedShell,
        ));
    }

    if matches!(executable, "nc" | "ncat" | "netcat") {
        let executes_shell = tokens.windows(2).any(|pair| {
            matches!(pair[0].as_str(), "-e" | "--exec") && is_recognized_shell(&pair[1])
        });
        if executes_shell {
            let network_mode = if tokens
                .iter()
                .any(|arg| matches!(arg.as_str(), "-l" | "--listen"))
            {
                NetworkMode::Bind
            } else {
                NetworkMode::ConnectBack
            };
            return Some(ReverseShellInput::new(
                network_mode,
                TransportClass::NetcatFamily,
                ExecutedProgramClass::RecognizedShell,
            ));
        }
    }

    if executable == "socat" {
        let has_network = tokens.iter().any(|arg| {
            let upper = arg.to_ascii_uppercase();
            upper.starts_with("TCP:")
                || upper.starts_with("TCP4:")
                || upper.starts_with("TCP-LISTEN:")
        });
        let executes_shell = tokens.iter().any(|arg| {
            let upper = arg.to_ascii_uppercase();
            upper.starts_with("EXEC:")
                && arg.split_once(':').is_some_and(|(_, program)| {
                    is_recognized_shell(program.split(',').next().unwrap_or(program))
                })
        });
        if has_network && executes_shell {
            return Some(ReverseShellInput::new(
                NetworkMode::ConnectBack,
                TransportClass::Socat,
                ExecutedProgramClass::RecognizedShell,
            ));
        }
    }

    None
}

fn is_recognized_shell(program: &str) -> bool {
    matches!(
        executable_name(program),
        "sh" | "bash" | "dash" | "ksh" | "zsh" | "cmd" | "cmd.exe" | "powershell" | "pwsh"
    )
}

pub fn evaluate(mode: MonitorMode, input: &EvaluationInput) -> Evaluation {
    if mode == MonitorMode::Off {
        return Evaluation {
            decision: LocalDecision::Off,
            finding: None,
        };
    }

    match input {
        EvaluationInput::Delete(input) => evaluate_delete(*input),
        EvaluationInput::DownloadPipeline(input) => evaluate_download(*input),
        EvaluationInput::ReverseShell(input) => evaluate_reverse_shell(*input),
    }
}

fn evaluate_delete(input: DeleteInput) -> Evaluation {
    if input.parser_status != ParserStatus::Complete
        || input.dialect == ShellDialect::Unavailable
        || input.target_class == TargetClass::Unavailable
        || input.target_expansion == TargetExpansion::Unavailable
    {
        return unavailable();
    }
    if input.execution_context != ExecutionContext::ParsedCommand {
        return no_match();
    }

    let protected_target = input.target_class == TargetClass::FilesystemRoot
        || (input.target_class == TargetClass::UserHome
            && input.target_expansion == TargetExpansion::Confirmed);
    if input.recursive && input.forced && protected_target {
        monitor_match(SafeFinding {
            rule_id: "trackai.exec.destructive_recursive_delete",
            rule_version: "1.5",
            severity: "critical",
            alert_title: "Large deletion requested",
            effect: "monitor",
            phase: "requested",
        })
    } else {
        no_match()
    }
}

fn evaluate_download(input: DownloadPipelineInput) -> Evaluation {
    if input.parser_status != ParserStatus::Complete
        || input.download_source == DownloadSource::Unavailable
        || input.output_disposition == OutputDisposition::Unavailable
        || input.interpreter_class == InterpreterClass::Unavailable
        || input.interpreter_input == InterpreterInput::Unavailable
    {
        return unavailable();
    }
    if input.execution_context != ExecutionContext::ParsedCommand {
        return no_match();
    }

    let executes_downloaded_input = input.output_disposition == OutputDisposition::Pipeline
        && matches!(
            input.interpreter_class,
            InterpreterClass::Shell | InterpreterClass::ScriptInterpreter
        )
        && input.interpreter_input == InterpreterInput::DownloaderStdout;
    if executes_downloaded_input {
        monitor_match(SafeFinding {
            rule_id: "trackai.exec.download_pipe_shell",
            rule_version: "1.4",
            severity: "high",
            alert_title: "Downloaded content requested for immediate execution",
            effect: "monitor",
            phase: "requested",
        })
    } else {
        no_match()
    }
}

fn evaluate_reverse_shell(input: ReverseShellInput) -> Evaluation {
    if input.parser_status != ParserStatus::Complete
        || input.network_mode == NetworkMode::Unavailable
        || input.transport_class == TransportClass::Unavailable
        || input.executed_program_class == ExecutedProgramClass::Unavailable
    {
        return unavailable();
    }
    if input.execution_context != ExecutionContext::ParsedCommand {
        return no_match();
    }

    let network_shell = matches!(
        input.network_mode,
        NetworkMode::ConnectBack | NetworkMode::Bind
    ) && matches!(
        input.transport_class,
        TransportClass::DeviceRedirect | TransportClass::NetcatFamily | TransportClass::Socat
    ) && input.executed_program_class == ExecutedProgramClass::RecognizedShell;
    if network_shell {
        monitor_match(SafeFinding {
            rule_id: "trackai.exec.reverse_shell",
            rule_version: "1.3",
            severity: "high",
            alert_title: "Remote command channel requested",
            effect: "monitor",
            phase: "requested",
        })
    } else {
        no_match()
    }
}

fn no_match() -> Evaluation {
    Evaluation {
        decision: LocalDecision::NoMatch,
        finding: None,
    }
}

fn unavailable() -> Evaluation {
    Evaluation {
        decision: LocalDecision::Unavailable,
        finding: None,
    }
}

fn monitor_match(finding: SafeFinding) -> Evaluation {
    Evaluation {
        decision: LocalDecision::MonitorMatch,
        finding: Some(finding),
    }
}
