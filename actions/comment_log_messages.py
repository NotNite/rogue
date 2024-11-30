from binaryninja import (
    BackgroundTaskThread,
    BinaryView,
    HighLevelILConst,
    HighLevelILOperation,
    HighLevelILCall,
)
import typing
from ..util import sheet

TAG_EMOJI = "📝"


class CommentLogMessages(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Commenting log messages...", True)
        self.bv = bv

    def run(self):
        log_messages = {}
        for row in sheet("LogMessage"):
            log_messages[row["RowId"]] = row["Text"]

        self.do_the_thing(
            "Client::UI::Misc::RaptureLogModule.ShowLogMessage", 1, log_messages
        )

    def do_the_thing(self, func_name: str, arg_index: int, lookup: dict[int, str]):
        func = self.bv.get_functions_by_name(func_name)[0]
        for ref in func.caller_sites:
            if self.cancelled:
                break

            try:
                for insn in ref.hlil.instruction_operands:
                    if insn.operation != HighLevelILOperation.HLIL_CALL:
                        continue

                    insn = typing.cast(HighLevelILCall, insn)
                    if len(insn.params) < (arg_index + 1):
                        continue

                    arg = insn.params[arg_index]
                    if arg.operation != HighLevelILOperation.HLIL_CONST:
                        continue

                    arg = typing.cast(HighLevelILConst, arg)

                    if arg.constant not in lookup:
                        continue
                    ref.function.set_comment_at(ref.address, lookup[arg.constant])
                    ref.function.add_tag(
                        "LogMessage",
                        lookup[arg.constant],
                        ref.address,
                    )
            except Exception as e:
                print(e)
                pass


def comment_log_messages(bv: BinaryView):
    task = CommentLogMessages(bv)
    task.start()
