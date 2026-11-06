"""Host and policy rules: shell escapes, restarts, explicit and unknown commands."""

from __future__ import annotations

from collections.abc import Iterable

from gcodeguard.commands import is_known
from gcodeguard.model import Action, Category, Finding, Severity
from gcodeguard.rules.base import Context, Rule


class ShellCommand(Rule):
    id = "host.shell"
    category = Category.HOST
    severity = Severity.CRITICAL
    summary = "Runs a shell command on the printer host (full host compromise)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        if ctx.cmd.code == "RUN_SHELL_COMMAND":
            target = ctx.cmd.str_param("CMD", "?")
            yield self.hit(ctx, f"RUN_SHELL_COMMAND executes '{target}' on the host computer")


class Restart(Rule):
    id = "host.restart"
    category = Category.HOST
    severity = Severity.WARNING
    summary = "Restarts firmware or the host (kills an in-progress print)."

    _CODES = {"RESTART", "FIRMWARE_RESTART", "M999", "@RESTART"}

    def check(self, ctx: Context) -> Iterable[Finding]:
        if ctx.cmd.code in self._CODES:
            severity = Severity.CRITICAL if ctx.state.is_printing else None
            yield self.hit(ctx, f"{ctx.cmd.code} restarts the controller", severity=severity)


class ExplicitBlock(Rule):
    id = "policy.blocked_command"
    category = Category.POLICY
    severity = Severity.CRITICAL
    summary = "Command is on the policy's block list."

    def check(self, ctx: Context) -> Iterable[Finding]:
        if ctx.cmd.code in ctx.policy.commands.block:
            yield self.hit(ctx, f"{ctx.cmd.code} is blocked by policy", action=Action.BLOCK)


class UnknownCommand(Rule):
    id = "policy.unknown_command"
    category = Category.POLICY
    severity = Severity.WARNING
    summary = "Command GcodeGuard does not recognise and the policy does not allow."

    def check(self, ctx: Context) -> Iterable[Finding]:
        code = ctx.cmd.code
        commands = ctx.policy.commands
        if commands.unknown is Action.ALLOW or code in commands.allow or is_known(code):
            return
        if code in commands.block:
            return  # ExplicitBlock already reports it
        yield self.hit(
            ctx,
            f"unrecognised command {code} (add it to commands.allow if it is one of your macros)",
            action=commands.unknown,
            severity=Severity.CRITICAL if commands.unknown is Action.BLOCK else None,
        )
