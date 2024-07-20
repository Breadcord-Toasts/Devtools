import contextlib
import inspect
import io
import json
import os
import re
import sys
import textwrap
import warnings
from pathlib import Path
from pprint import pprint
from typing import Any

import aiohttp
import discord
from discord.ext import commands

import breadcord
from breadcord.config import Setting
from breadcord.helpers import make_codeblock

_Undefined = type("_Undefined", (), {"__repr__": lambda _: "UNDEFINED"})
UNDEFINED = _Undefined()


class ANSIEscape:
    def __init__(self, *code: int, prefix: str = "\033[", suffix: str = "m"):
        self.code = map(str, code)
        self._prefix = prefix
        self._suffix = suffix

    def __str__(self) -> str:
        return self._prefix + ";".join(self.code) + self._suffix

    def __repr__(self) -> str:
        return f"ANSIEscape({', '.join(self.code)})"

    def __len__(self) -> int:
        return len(str(self))


def format_embed_desc(items: dict[str, Any | None]) -> str:
    return "\n".join(
        f"**{key}:** {value}" if key else value
        for key, value in items.items()
        if value is not None
    )


def get_codeblock_content(
    codeblock: str,
    *,
    greedy: bool = True,
    language_regex: str = "[a-z]+?",
    optional_lang: bool = True,
    strip_inline: bool = True,
    cleanup: bool = True,
) -> str:
    """
    Removes a codeblock surrounding a string and returns the content inside it.
    If no codeblock is found, the original string is returned.

    :param codeblock: The string to process.
    :param greedy: Whether to consume codeblock content greedily.
        The default behaviour is greedy, but the discord client renders codeblocks using a non-greedy approach.
        Greedy matching usually aligns closer with the user's intent when passed as an argument, however.
    :param language_regex: Regex in string form used to match the language of the codeblock. For example, "py(thon)?".
    :param optional_lang: Whether the language is optional. Ignored if "language_regex" is empty.
    :param strip_inline: Whether to strip inline codeblocks.
    :param cleanup: Whether clean up the codeblock content by dedenting and stripping empty lines.
    :return: The content inside the codeblock, or the original string if no codeblock was found.
    """
    stripped = codeblock.strip()

    if strip_inline:
        if len(stripped) >= 3 and (
            stripped[0] == "`" and stripped[-1] == "`"
        ) and not (
            stripped[1] == "`" or stripped[-2] == "`"
        ):
            return stripped[1:-1]

    if not (stripped.startswith("```") and stripped.endswith("```")):
        return codeblock

    if language_regex and not language_regex.endswith("\n"):
        language_regex = f"{language_regex}\n"
    # noinspection RegExpUnnecessaryNonCapturingGroup
    regex = re.compile(
        rf"""
        ```
        (?P<language>(?:{language_regex}){'?' if language_regex and optional_lang else ''}
        (?P<content>.+{'' if greedy else '?'})
        ```
        """,
        flags=re.DOTALL | re.IGNORECASE | re.VERBOSE,
    )
    match = regex.match(stripped)
    if not match:
        return codeblock

    content = match["content"]
    if not cleanup:
        return content

    lines = content.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    content = "\n".join(lines)
    return textwrap.dedent(content)


async def format_exec_output_as_kwargs(
    return_value: Any | _Undefined,
    exception: Exception | _Undefined,
    stdout: str | None,
    stderr: str | None,
) -> dict[str, Any]:
    def output_segment(*, value: Any, title: str, colour: bool = False) -> str:
        return (
            f"**{discord.utils.escape_markdown(title)}**"
            + make_codeblock(str(value), lang='ansi' if colour else None)
        )

    output = ""
    if return_value is not UNDEFINED:
        output += output_segment(value=return_value, title="Return value")
    if exception is not UNDEFINED:
        output += output_segment(value=exception, title="Exception")
    if stdout:
        output += output_segment(value=stdout, title="Output stream", colour=True)
    if stderr:
        output += output_segment(value=stderr, title="Error stream", colour=True)

    if not output:
        return dict(content="No output")
    if len(output) <= 2000:
        return dict(content=output)
    else:
        return dict(
            content="Output too big, uploading as file(s).",
            attachments=[
                discord.File(io.BytesIO(str(content).encode()), filename=filename)
                for content, filename in (
                    (return_value, "return.txt"),
                    (exception, "exception.txt"),
                    (stdout or UNDEFINED, "stdout.txt"),
                    (stderr or UNDEFINED, "stderr.txt")
                )
                if content is not UNDEFINED
            ],
        )


ALLOWED_RE_FLAGS: dict[str, re.RegexFlag] = {
    "ASCII": re.RegexFlag.ASCII,
    "A": re.RegexFlag.ASCII,
    "IGNORECASE": re.RegexFlag.IGNORECASE,
    "I": re.RegexFlag.IGNORECASE,
    "LOCALE": re.RegexFlag.LOCALE,
    "L": re.RegexFlag.LOCALE,
    "UNICODE": re.RegexFlag.UNICODE,
    "U": re.RegexFlag.UNICODE,
    "MULTILINE": re.RegexFlag.MULTILINE,
    "M": re.RegexFlag.MULTILINE,
    "DOTALL": re.RegexFlag.DOTALL,
    "S": re.RegexFlag.DOTALL,
    "VERBOSE": re.RegexFlag.VERBOSE,
    "X": re.RegexFlag.VERBOSE,
}

DEFAULT_GLOBALS = dict(
    __builtins__=__builtins__,
    breadcord=breadcord,
    discord=discord,
    commands=commands,
    re=re,
    json=json,
    os=os,
    sys=sys,
    pprint=pprint,
    pp=pprint,
    Path=Path,
    io=io,
)


class Devtools(breadcord.module.ModuleCog):
    def __init__(self, module_id: str) -> None:
        super().__init__(module_id)

        setting: Setting = self.settings.enable_unsafe_commands  # pyright: ignore [reportAssignmentType]

        @setting.observe
        def on_rce_commands_changed(_, new: bool) -> None:
            self.logger.info(f"Potentially unsafe commands {'enabled' if new else 'disabled'}.")
            self.evaluate.enabled = new
            self.execute.enabled = new

        on_rce_commands_changed(None, setting.value)

    async def cog_load(self) -> None:
        DEFAULT_GLOBALS["session"] = aiohttp.ClientSession()

    async def cog_unload(self) -> None:
        await DEFAULT_GLOBALS["session"].close()
        del DEFAULT_GLOBALS["session"]

    @discord.app_commands.command()
    async def regex_test(self, interaction: discord.Interaction, *, regex: str, match_against: str, flags: str = ""):
        filtered_flags: list[re.RegexFlag] = []
        for flag in flags.replace(",", " ").split():
            flag = flag.upper().strip()
            if not flag:
                continue
            if flag not in ALLOWED_RE_FLAGS:
                await interaction.response.send_message(embed=discord.Embed(
                    color=discord.Colour.red(),
                    title="Error",
                    description=(
                        "Invalid flag(s) provided. "
                        "For a list of valid flags, see <https://docs.python.org/3.12/library/re.html#flags>"
                    ),
                ))
                return
            filtered_flags.append(ALLOWED_RE_FLAGS[flag])
        flag_bitfield: int = sum(flag.value for flag in filtered_flags)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                compiled = re.compile(regex, flags=flag_bitfield)
        except re.error as error:
            await interaction.response.send_message(embed=discord.Embed(
                color=discord.Colour.red(),
                title="Error",
                description=str(error)[0].title() + str(error)[1:],
            ))
            return

        found_matches = tuple(compiled.finditer(match_against))
        if found_matches:
            colours: tuple[int, ...] = (
                31,  # Red
                33,  # Yellow
                32,  # Green
                36,  # Cyan
                34,  # Blue
                35,  # Magenta
            )
            start_indices = tuple(match.start() for match in found_matches)
            end_indices = tuple(match.end() for match in found_matches)
            match_codeblock = ""
            color_index = 0
            for index, character in enumerate(match_against):
                if index in end_indices and index not in start_indices:
                    match_codeblock += str(ANSIEscape(0))  # Reset colour
                if index in start_indices:
                    colour = colours[color_index]
                    color_index = (color_index + 1) % len(colours)
                    match_codeblock += str(ANSIEscape(colour))
                match_codeblock += character
            match_codeblock = f"```ansi\n{match_codeblock}\n```"
        else:
            match_codeblock = "No matches found."

        await interaction.response.send_message(embed=(
            discord.Embed(
                color=discord.Colour.green(),
                title="Results",
                description=format_embed_desc({
                    "Regex": f"```regex\n{regex}```",  # Maybe one day there will be syntax highlighting for regex...
                    "Flags": ", ".join(f"`{flag.name}`" for flag in filtered_flags) if compiled.flags else None,
                    "Matches": match_codeblock,
                }),
            )
            .set_footer(text=f"Total matches: {len(found_matches)}")
        ))

    @commands.command(aliases=["eval"], enabled=False)
    @commands.is_owner()
    async def evaluate(self, ctx: commands.Context, *, code: str) -> None:
        """Evaluates python code. (blocking)"""
        # language=regexp
        code = get_codeblock_content(code, language_regex=r"py(thon)?")
        spoofed_globals: dict = DEFAULT_GLOBALS | dict(
            ctx=ctx,
            bot=self.bot,
        )
        if ctx.message.reference:
            spoofed_globals["reference"] = ctx.message.reference.cached_message
        response = await ctx.reply("Evaluating...")

        return_value = UNDEFINED
        exception = UNDEFINED
        with (
            contextlib.redirect_stdout(io.StringIO()) as stdout,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            try:
                return_value = eval(code, spoofed_globals, {})
                if inspect.isawaitable(return_value):
                    return_value = await return_value
            except Exception as error:
                exception = error

        await response.edit(**await format_exec_output_as_kwargs(
            return_value=return_value,
            exception=exception,
            stdout=stdout.getvalue(),
            stderr=stderr.getvalue(),
        ))

    @commands.command(aliases=["exec"], enabled=False)
    @commands.is_owner()
    async def execute(self, ctx: commands.Context, *, code: str) -> None:
        """Executes python code. (blocking)"""
        # language=regexp
        code = get_codeblock_content(code, language_regex=r"py(thon)?")
        to_execute = "async def _execute():\n" + "\n".join(
            f"    {line}" for line in code.splitlines()
        )
        spoofed_globals: dict = DEFAULT_GLOBALS | dict(
            ctx=ctx,
            bot=self.bot,
        )
        if ctx.message.reference:
            spoofed_globals["reference"] = ctx.message.reference.cached_message

        response = await ctx.reply("Executing...")

        return_value = UNDEFINED
        exception = UNDEFINED
        with (
            contextlib.redirect_stdout(io.StringIO()) as stdout,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            spoofed_locals = {}
            try:
                exec(to_execute, spoofed_globals, spoofed_locals)
                return_value = (await spoofed_locals["_execute"]()) or UNDEFINED
            except Exception as error:
                exception = error

        await response.edit(**await format_exec_output_as_kwargs(
            return_value=return_value,
            exception=exception,
            stdout=stdout.getvalue(),
            stderr=stderr.getvalue(),
        ))


async def setup(bot: breadcord.Bot, module: breadcord.module.Module) -> None:
    await bot.add_cog(Devtools(module.id))
