import asyncio

import discord


class ShellInputModal(discord.ui.Modal, title="Shell input"):
    shell_input = discord.ui.TextInput(
        label="Input",
        placeholder="Input to send to the running shell. Escape sequences will be processed.",
        style=discord.TextStyle.long,
    )

    def __init__(self, process: asyncio.subprocess.Process):
        super().__init__()
        self.process = process

    async def on_submit(self, interaction: discord.Interaction):
        stdin: asyncio.StreamWriter = self.process.stdin  # type: ignore  # It won't be None
        stdin.write(self.shell_input.value.encode().decode("unicode_escape").encode())
        await interaction.response.defer()


class ShellView(discord.ui.View):
    def __init__(self, process: asyncio.subprocess.Process, *, user_id: int) -> None:
        super().__init__(timeout=None)
        self.process = process
        self.user_id = user_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.user_id:
            await interaction.response.send_message(
                f'Only <@{self.user_id}> can perform this action!',
                ephemeral=True
            )
            return False
        return True

    @discord.ui.button(label='Cancel', style=discord.ButtonStyle.red)
    async def cancel(self, *_) -> None:
        self.process.terminate()
        self.stop()

    @discord.ui.button(label='Send input', style=discord.ButtonStyle.gray)
    async def send_input(self, interaction: discord.Interaction, _) -> None:
        input_modal = ShellInputModal(self.process)
        await interaction.response.send_modal(input_modal)
