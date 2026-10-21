#!/bin/sh
# Task20b: measure Numbat binary size, hook latency, and Git AI checkpoint
# latency for the TrackAI budgets (TASK20 section 6).
#
# Usage: measure.sh <numbat-binary> [<git-ai-binary>]
#
# Isolation (TrackAI AGENTS.md s9 item 6): every run uses a throwaway HOME and
# a throwaway `git init` repository as the working directory; inherited
# GIT_AI_* and GIT_TRACE2* pointers, XDG_CONFIG_HOME and Git global/system
# config overrides are stripped before any git or git-ai command runs, so the
# developer's own daemon is never started, stopped or contacted. The Git AI
# case runs only with GIT_AI_MEASURE=1. Prints sizes and median / p95 / max
# latency per case. Never prints payload contents, record contents, or paths
# outside the throwaway directory.
set -eu

stripped_flag() {
    # Spec: `nm "$bin" | wc -l` on macOS; 0 lines or "no symbols" means
    # stripped. nm emits "no symbols" on stderr for a fully stripped binary,
    # on stdout when it has only that note.
    if ! command -v nm >/dev/null 2>&1; then
        echo unknown
        return 0
    fi
    nm_text=$(nm "$1" 2>&1 | head -3)
    case "$nm_text" in
    "no symbols" | "") echo yes ;;
    *) echo no ;;
    esac
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <numbat-binary> [<git-ai-binary>] (git-ai runs only with GIT_AI_MEASURE=1)" >&2
    exit 2
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

numbat_bin=$1
if [ ! -x "$numbat_bin" ]; then
    echo "measure.sh: numbat binary not executable" >&2
    exit 1
fi
numbat_bin=$(CDPATH='' cd -- "$(dirname -- "$numbat_bin")" && pwd)/$(basename -- "$numbat_bin")

# The git-ai default location is resolved before the throwaway HOME replaces
# the real one.
git_ai_bin=${2:-}
if [ -z "$git_ai_bin" ] && [ -x "$HOME/.git-ai/bin/git-ai" ]; then
    git_ai_bin="$HOME/.git-ai/bin/git-ai"
fi
if [ -n "$git_ai_bin" ] && [ -x "$git_ai_bin" ]; then
    git_ai_bin=$(CDPATH='' cd -- "$(dirname -- "$git_ai_bin")" && pwd)/$(basename -- "$git_ai_bin")
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/trackai-measure.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

# --- sizes -------------------------------------------------------------------

if command -v sha256sum >/dev/null 2>&1; then
    nb_digest=$(sha256sum "$numbat_bin" | awk '{print $1}')
else
    nb_digest=$(shasum -a 256 "$numbat_bin" | awk '{print $1}')
fi
echo "size numbat: $(wc -c <"$numbat_bin" | tr -d ' ') bytes sha256=$nb_digest stripped=$(stripped_flag "$numbat_bin")"

if [ -n "$git_ai_bin" ] && [ -x "$git_ai_bin" ]; then
    echo "size git-ai: $(wc -c <"$git_ai_bin" | tr -d ' ') bytes stripped=$(stripped_flag "$git_ai_bin")"
else
    echo "size git-ai: unavailable (binary not found)"
    git_ai_bin=
fi

# --- latency ------------------------------------------------------------------
# Each timed sample is one fork/exec of the target binary in a throwaway HOME
# and throwaway repository (no extra shell spawn inside the sample):
# 10 warm-up runs, then 200 timed runs per case.

if ! command -v perl >/dev/null 2>&1; then
    echo "measure.sh: perl missing; size results only" >&2
    exit 0
fi

export THROWAWAY_HOME="$tmp/home"
export RUN_REPO="$tmp/repo"
export RUN_STDERR_LOG="$tmp/run.stderr"
export NUMBAT_BIN="$numbat_bin"
export MEASURE_GIT_AI_BIN="$git_ai_bin"
RUNS=200
WARMUP=10
export RUNS WARMUP

# Isolation is applied to this shell itself BEFORE any git or git-ai command:
# the throwaway home mkdir and the throwaway `git init` must not see the
# developer's configuration or daemon pointers.
measure_git_ai_measure=${GIT_AI_MEASURE:-}
unset_git_ai_and_trace_vars() {
    for v in $(env | sed -n 's/^\(GIT_AI_[A-Za-z0-9_]*\)=.*/\1/p'); do
        unset "$v"
    done
    for v in $(env | sed -n 's/^\(GIT_TRACE2[A-Za-z0-9_]*\)=.*/\1/p'); do
        unset "$v"
    done
    unset GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM XDG_CONFIG_HOME || true
}
unset_git_ai_and_trace_vars
# Re-export only the measurement switches this script itself owns.
if [ -n "$measure_git_ai_measure" ]; then
    export GIT_AI_MEASURE="$measure_git_ai_measure"
fi
export HOME="$tmp/home"
export XDG_CONFIG_HOME="$tmp/home/.config"
export GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME"
git init -q "$RUN_REPO"

NUMBAT_HOOK_BENIGN="$script_dir/fixtures/claude-pretooluse-benign.json" \
    NUMBAT_HOOK_MATCH="$script_dir/fixtures/claude-pretooluse-match.json" \
    NUMBAT_OUTPUT_FILE="$tmp/records.ndjson" \
    perl <<'PERL'
use strict; use warnings;
use Time::HiRes qw(gettimeofday tv_interval);

my $runs    = $ENV{RUNS};
my $warmup  = $ENV{WARMUP};
my $repo    = $ENV{RUN_REPO};
my $home    = $ENV{THROWAWAY_HOME};
my $errlog  = $ENV{RUN_STDERR_LOG};

sub truncate_file { open my $fh, '>', $_[0] or die "truncate: $!"; close $fh; }

sub timed_run {
    my ($fixture, @proc) = @_;
    my $t0 = [gettimeofday()];
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDIN,  '<',  $fixture        or die "stdin: $!";
        open STDOUT, '>>', $ENV{NUMBAT_OUTPUT_FILE} or die "stdout: $!";
        open STDERR, '>>', $errlog         or die "stderr: $!";
        exec { $proc[0] } @proc or die "exec failed";
    }
    waitpid $pid, 0;
    return (tv_interval($t0) * 1000.0, $? >> 8);
}

sub reason_from_log {
    open my $fh, '<', $errlog or return "reason unavailable";
    my $text = do { local $/; <$fh> };
    close $fh;
    return "daemon not available"  if $text =~ /daemon/i;
    return "configuration not found in throwaway home" if $text =~ /config/i;
    return "reason unreported";
}

sub run_case {
    my ($name, $fixture, @proc) = @_;
    chdir $repo or die "chdir repo: $!";
    $ENV{HOME} = $home;

    my @times;
    my $bad;
    for my $i (1 .. $warmup + $runs) {
        truncate_file($ENV{NUMBAT_OUTPUT_FILE});
        truncate_file($errlog);
        my ($ms, $code) = timed_run($fixture, @proc);
        if ($i <= $warmup) {
            if ($code != 0) {
                my $why = $name eq 'git-ai-hook' ? reason_from_log() : "exit $code";
                print "$name: unavailable ($why)\n";
                return;
            }
            next;
        }
        push @times, $ms;
        $bad = "exit $code" if $code != 0 && !defined $bad;
    }
    if (defined $bad) {
        my $why = $name eq 'git-ai-hook' ? reason_from_log() : $bad;
        print "$name: unavailable ($why)\n";
        return;
    }
    my @sorted = sort { $a <=> $b } @times;
    my $n = scalar @sorted;
    my $median;
    if ($n % 2) { $median = $sorted[int($n / 2)]; }
    else        { $median = ($sorted[$n / 2 - 1] + $sorted[$n / 2]) / 2; }
    my $p95_idx = int($n * 0.95) >= $n ? $n - 1 : int($n * 0.95);
    printf("%s: median=%.1fms p95=%.1fms max=%.1fms n=%d\n",
        $name, $median, $sorted[$p95_idx], $sorted[-1], $n);
}

my @hook_args = ("hook", "PreToolUse", "--agent", "claude",
                 "--output-file", $ENV{NUMBAT_OUTPUT_FILE});

run_case("numbat-hook-benign", $ENV{NUMBAT_HOOK_BENIGN}, $ENV{NUMBAT_BIN}, @hook_args);
run_case("numbat-hook-match",  $ENV{NUMBAT_HOOK_MATCH},  $ENV{NUMBAT_BIN}, @hook_args);

exit 0 unless $ENV{GIT_AI_MEASURE} && $ENV{GIT_AI_MEASURE} eq "1";
if (!$ENV{MEASURE_GIT_AI_BIN} || !-x $ENV{MEASURE_GIT_AI_BIN}) {
    print "git-ai-hook: unavailable (binary not found)\n";
    exit 0;
}
run_case("git-ai-hook", $ENV{NUMBAT_HOOK_BENIGN}, $ENV{MEASURE_GIT_AI_BIN},
    "checkpoint", "claude", "--hook-input", "stdin");
PERL
