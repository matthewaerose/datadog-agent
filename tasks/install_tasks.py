import os
import sys
from pathlib import Path

from invoke import Context, Exit, task

from tasks.libs.common.color import Color, color_message
from tasks.libs.common.go import download_go_dependencies
from tasks.libs.common.retry import run_command_with_retry
from tasks.libs.common.utils import environ, get_gobin, gitlab_section, link_or_copy

TOOL_LIST = [
    'github.com/bazelbuild/bazelisk',
    'github.com/frapposelli/wwhrd',
    'github.com/go-enry/go-license-detector/v4/cmd/license-detector',
    'github.com/golangci/golangci-lint/v2/cmd/golangci-lint',
    'github.com/goware/modvendor',
    'github.com/stormcat24/protodep',
    'gotest.tools/gotestsum',
    'github.com/vektra/mockery/v3',
    'github.com/wadey/gocovmerge',
    'github.com/uber-go/gopatch',
    'github.com/aarzilli/whydeadcode',
]

TOOLS = {
    'internal/tools': TOOL_LIST,
}


@task
def download_tools(ctx):
    """Download all Go tools for testing."""
    print(color_message("This command is deprecated, please use `install-tools` instead", Color.ORANGE))
    with environ({'GO111MODULE': 'on'}):
        download_go_dependencies(ctx, paths=list(TOOLS.keys()))


@task
def install_tools(ctx: Context, max_retry: int = 3, verbose: bool = False):
    """Install all Go tools for testing."""
    with gitlab_section("Installing Go tools", collapsed=True):
        env = {'GO111MODULE': 'on'}
        if os.getenv('DD_CC'):
            env['CC'] = os.getenv('DD_CC')
        if os.getenv('DD_CXX'):
            env['CXX'] = os.getenv('DD_CXX')
        verbose_flag = " -x" if verbose else ""
        with environ(env):
            for path, tools in TOOLS.items():
                with ctx.cd(path):
                    for tool in tools:
                        run_command_with_retry(ctx, f"go install{verbose_flag} {tool}", max_retry=max_retry)
        for bazelisk in Path(get_gobin(ctx)).glob('bazelisk*'):
            link_or_copy(bazelisk, bazelisk.with_stem(bazelisk.stem.replace('isk', '')))


@task
def install_shellcheck(ctx, version="0.8.0", destination="/usr/local/bin"):
    """
    Installs the requested version of shellcheck in the specified folder (by default /usr/local/bin).
    Required to run the shellcheck pre-commit hook.
    """

    if sys.platform == 'win32':
        print("shellcheck is not supported on Windows")
        raise Exit(code=1)
    if sys.platform.startswith('darwin'):
        platform = "darwin"
    if sys.platform.startswith('linux'):
        platform = "linux"

    ctx.run(
        f"wget -qO- \"https://github.com/koalaman/shellcheck/releases/download/v{version}/shellcheck-v{version}.{platform}.x86_64.tar.xz\" | tar -xJv -C /tmp"
    )
    ctx.run(f"cp \"/tmp/shellcheck-v{version}/shellcheck\" {destination}")
    ctx.run(f"rm -rf \"/tmp/shellcheck-v{version}\"")


@task
def install_rust_license_tool(ctx):
    """
    Install dd-rust-license-tool and cargo-deny for Rust license verification.
    Required to run the lint-rust-licenses task.
    """
    ctx.run("cargo install --git https://github.com/DataDog/rust-license-tool dd-rust-license-tool")
    ctx.run("cargo install cargo-deny --locked")


@task
def install_devcontainer_cli(ctx):
    """
    Install the devcontainer CLI
    """
    ctx.run("npm install -g @devcontainers/cli")
