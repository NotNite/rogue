import os
import re
import struct
import typing
import yaml
from binaryninja import (
    BackgroundTaskThread,
    BinaryView,
    StructureBuilder,
    Type,
    TypeBuilder,
    get_choice_input,
)
from ..settings import settings, CS_DIR


class Structs(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Importing structs...", True)
        self.bv = bv
        self.logger = bv.create_logger("rogue.actions.structs")

    def run(self):
        cs_dir = settings.get_string(CS_DIR)
        if not cs_dir:
            raise ValueError("ClientStructs directory not set")

        structs_yml = os.path.join(
            settings.get_string(CS_DIR), "ida", "ffxiv_structs.yml"
        )
        if not os.path.exists(structs_yml):
            raise FileNotFoundError("ffxiv_structs.yml not found")

        self.logger.log_info(f"Loading structs from {structs_yml}")
        data = None
        with open(structs_yml, "r") as f:
            data = yaml.safe_load(f)

        self.logger.log_info("Importing enums")
        for enum in data["enums"]:
            self.handle_enum(enum)

        self.logger.log_info("Creating struct forward declarations")
        self.handle_structs_forward_decl(data["structs"])

        self.logger.log_info("Importing structs")
        for struct in data["structs"]:
            self.handle_struct(struct)

        if self.yes_no("Import struct member functions?"):
            for struct in data["structs"]:
                self.handle_member_functions(struct)

        # if self.yes_no("Import struct virtual functions?"):
        #     for struct in data["structs"]:
        #         self.handle_virtual_functions(struct)

        self.logger.log_info("Waiting for analysis to complete")
        self.bv.update_analysis_and_wait()

        self.logger.log_info("Structs imported :3")

    def yes_no(self, prompt: str):
        return (
            get_choice_input(
                prompt,
                "Rogue",
                ["Yes", "No"],
            )
            == 0
        )

    def parse_type_string_wrapped(self, type_str: str):
        try:
            pointerless_str = type_str.rstrip("*")
            wrapped_type_str = f"`{pointerless_str}`"
            pointer_count = len(type_str) - len(pointerless_str)
            for _ in range(pointer_count):
                wrapped_type_str += "*"

            return self.bv.parse_type_string(wrapped_type_str)[0]
        except Exception as e:
            self.logger.log_error(f"Failed to parse type string {type_str}: {e}")
            return None

    def parse_type(self, type_str: str):
        # Misc
        if type_str == "void":
            return Type.void()
        elif type_str == "char":
            return Type.char()
        elif type_str == "__fastcall":
            return None  # bro what???
        # Signed integers
        elif type_str == "__int8" or type_str == "byte":
            return Type.int(1, True)
        elif type_str == "__int16" or type_str == "short":
            return Type.int(2, True)
        elif type_str == "int" or type_str == "unsigned int":
            return Type.int(4, True)
        elif type_str == "__int64" or type_str == "unsigned __int64":
            return Type.int(8, True)
        # Unsigned integers
        elif type_str == "unsigned __int8":
            return Type.int(1, False)
        elif type_str == "unsigned __int16":
            return Type.int(2, False)
        elif type_str == "unsigned int":
            return Type.int(4, False)
        elif type_str == "unsigned __int64":
            return Type.int(8, False)
        # Floats
        elif type_str == "float":
            return Type.float(4)
        elif type_str == "double":
            return Type.float(8)
        # Just lookup the type
        else:
            # Pointer
            if type_str.endswith("*"):
                pointerless_str = type_str.rstrip("*")

                # TODO: below assumption is wrong I think
                # If they're still here, too complex! Must look it up with clang
                # if "*" in pointerless_str:
                #    return self.parse_type_string_wrapped(type_str)

                pointer_count = len(type_str) - len(pointerless_str)
                pointer_type = self.parse_type(pointerless_str)
                if pointer_type is None:
                    return None

                for _ in range(pointer_count):
                    pointer_type = Type.pointer(self.bv.arch, pointer_type)
                return pointer_type

            if type_str in self.bv.types:
                return self.bv.types[type_str]
            else:
                self.logger.log_warn(f"Hit slow path for lookup of {type_str}")
                return self.parse_type_string_wrapped(type_str)

    def handle_enum(self, enum):
        name = enum["type"]

        underlying = self.parse_type(enum["underlying"])
        if underlying is None:
            self.logger.log_warn(
                f"Failed to parse underlying type {enum['underlying']}"
            )
            return

        members = []
        for key, value in enum["values"].items():
            members.append((key, value))
        type_builder = TypeBuilder.enumeration(self.bv.arch, members, underlying.width)
        self.bv.define_user_type(name, type_builder)

    def handle_structs_forward_decl(self, structs):
        for struct in structs:
            name = struct["type"]
            union = struct["union"]
            underlying_type = TypeBuilder.union() if union else TypeBuilder.structure()
            self.bv.define_user_type(name, underlying_type)

    def handle_struct(self, struct):
        name = struct["type"]
        union = struct["union"]

        type_builder = self.bv.get_type_by_name(
            name
        ).mutable_copy()  # type: StructureBuilder
        type_builder.members = []

        if union:
            members = []

            for field in struct["fields"]:
                field_name = field["name"]
                field_type = self.parse_type(field["type"])
                if field_type is None:
                    self.logger.log_warn(f"Failed to parse type {field['type']}")
                    continue

                members.append((field_type, field_name))

            type_builder = TypeBuilder.union(members)
        else:
            for field in struct["fields"]:
                field_name = field["name"]
                field_type = self.parse_type(field["type"])
                if field_type is None:
                    self.logger.log_warn(f"Failed to parse type {field['type']}")
                    continue

                if "size" in field:
                    size = field["size"]
                    field_type = Type.array(field_type, size)

                type_builder.append(field_type, field_name)

        self.bv.define_user_type(name, type_builder)

    def handle_member_functions(self, struct):
        type = struct["type"]
        for member_function in struct["member_functions"]:
            name = member_function["name"]
            signature = member_function["signature"]
            return_type = member_function["return_type"]

            addr = self.get_func_ea_by_sig(signature)
            if addr is None:
                # self.logger.log_warn(f"Failed to find function {name}")
                continue

            func = self.bv.get_function_at(addr)
            if func is None:
                # self.logger.log_warn(f"Failed to find function {name}")
                continue

            func.name = f"{type}.{name}"
            func.return_type = self.parse_type(return_type)

            for i, parameter in enumerate(member_function["parameters"]):
                param_name = parameter["name"]
                param_type = self.parse_type(parameter["type"])
                if param_type is None:
                    self.logger.log_warn(f"Failed to parse type {parameter['type']}")
                    continue

                if i >= len(func.parameter_vars):
                    # self.logger.log_warn(
                    #     f"Function {name} has more parameters than expected"
                    # )
                    break

                parameter_var = func.parameter_vars[i]
                parameter_var.name = param_name
                parameter_var.type = param_type

    def handle_virtual_functions(self, struct):
        # TODO lol
        pass

    def get_func_ea_by_sig(self, pattern: str):
        regex = ""
        for part in pattern.split(" "):
            if part == "??":
                regex = regex + "."
            else:
                regex = regex + "\\x" + part
        compiled = re.compile(regex.encode("utf-8"))

        for segment in self.bv.segments:
            data = self.bv.read(segment.start, segment.end - segment.start)
            match = compiled.search(data)
            if match:
                match_start = match.start()
                addr = segment.start + match_start
                if data[match_start] == 0xE8 or data[match_start] == 0xE9:
                    addr += 5
                    addr += struct.unpack(
                        "<I", data[match_start + 1 : match_start + 5]
                    )[0]
                return addr


def structs(bv: BinaryView):
    task = Structs(bv)
    task.start()
