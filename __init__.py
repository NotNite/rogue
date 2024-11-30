from binaryninja import PluginCommand
from .actions.rename import rename
from .actions.comment_log_messages import comment_log_messages

PluginCommand.register(
    "Rogue\\Rename executable",
    "Apply names from FFXIVClientStructs' data.yml",
    rename,
)

PluginCommand.register(
    "Rogue\\Comment log messages",
    "Adds comments to ShowLogMessage and whatnot",
    comment_log_messages,
)
