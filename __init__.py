import ast
import base64
import math
import operator
import random
import re
import string
import warnings
from typing import Any, Iterable

import discord
from discord.ext import commands

import breadcord
import discord


def format_embed_desc(items: dict[str, Any | None]) -> str:
    return "\n".join(
        f"**{key}:** {value}" if key else value
        for key, value in items.items()
        if value is not None
    )


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


def regex_match_codeblock(matches: Iterable[re.Match[str]], match_against: str) -> str:
    matches = tuple(matches)
    if not matches:
        return "No matches found."

    colours: tuple[int, ...] = (
        31,  # Red
        33,  # Yellow
        32,  # Green
        36,  # Cyan
        34,  # Blue
        35,  # Magenta
    )

    start_indices = tuple(match.start() for match in matches)
    end_indices = tuple(match.end() for match in matches)

    output = ""
    current_match_count = 0
    for index, character in enumerate(match_against):
        if index in end_indices and index not in start_indices:
            output += str(ANSIEscape(0))  # Reset colour

        if index in start_indices:
            colour = colours[current_match_count % len(colours)]
            current_match_count += 1
            output += str(ANSIEscape(colour))

        output += character

    return f"```ansi\n{output}\n```"


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


class Devtools(breadcord.module.ModuleCog):
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
                    )
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
                description=str(error)[0].title() + str(error)[1:]
            ))
            return

        found_matches = tuple(compiled.finditer(match_against))
        await interaction.response.send_message(embed=(
            discord.Embed(
                color=discord.Colour.green(),
                title="Results",
                description=format_embed_desc({
                    "Regex": f"```regex\n{regex}```",  # Maybe one day there will be syntax highlighting for regex...
                    "Flags": ", ".join(f"`{flag.name}`" for flag in filtered_flags) if compiled.flags else None,
                    "Matches": regex_match_codeblock(found_matches, match_against) if found_matches else "No matches found."
                })
            )
            .set_footer(text=f"Total matches: {len(found_matches)}")
        ))


async def setup(bot: breadcord.Bot, module: breadcord.module.Module) -> None:
    await bot.add_cog(Devtools(module.id))
