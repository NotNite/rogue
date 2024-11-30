import os
import yaml
from binaryninja import BackgroundTaskThread, BinaryView, TypeBuilder
from ..settings import settings, CS_DIR


class Rename(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__("Renaming executable...", True)
        self.bv = bv
        self.void_ptr = TypeBuilder.pointer(bv.arch, TypeBuilder.void())
        self.logger = bv.create_logger("rogue.actions.rename")

    def parse_number(self, number_str):
        if type(number_str) == int:
            return number_str
        return int(number_str, 16)

    def run(self):
        cs_dir = settings.get_string(CS_DIR)
        if not cs_dir:
            raise ValueError("ClientStructs directory not set")

        data_yml = os.path.join(settings.get_string(CS_DIR), "ida", "data.yml")
        if not os.path.exists(data_yml):
            raise FileNotFoundError("data.yml not found")

        self.logger.log_info(f"Loading data from {data_yml}")
        data = None
        with open(data_yml, "r") as f:
            data = yaml.safe_load(f)

        self.logger.log_info("Renaming globals")
        for addr, name in data["globals"].items():
            addr = self.parse_number(addr)
            var = self.bv.get_data_var_at(addr)
            if var:
                var.name = name

        self.logger.log_info("Renaming loose functions")
        for addr, name in data["functions"].items():
            addr = self.parse_number(addr)
            func = self.bv.get_function_at(addr)
            if not func:
                func = self.bv.create_user_function(addr)
            if func:
                func.name = name

        self.logger.log_info("Renaming classes")
        for name, data in data["classes"].items():
            self.handle_class(name, data)

        self.logger.log_info("Waiting for analysis to complete")
        self.bv.update_analysis_and_wait()
        self.logger.log_info("Renaming complete :3")

    def handle_class(self, class_name, data):
        if data is None:
            return

        if "instances" in data and data["instances"]:
            for instance in data["instances"]:
                ea = self.parse_number(instance["ea"])
                pointer = instance["pointer"] if "pointer" in instance else False

                var = self.bv.get_data_var_at(ea)
                instance_type = self.bv.get_type_by_name(class_name)
                if instance_type and pointer:
                    instance_type = TypeBuilder.pointer(self.bv.arch, instance_type)
                if not instance_type:
                    instance_type = self.void_ptr

                instance_name = (
                    f"g_{class_name}_{instance['name']}"
                    if "name" in instance
                    else f"g_{class_name}"
                )

                if var:
                    var.type = instance_type
                    var.name = instance_name
                else:
                    var = self.bv.define_user_data_var(ea, instance_type, instance_name)

        if "funcs" in data and data["funcs"]:
            for ea, func_name in data["funcs"].items():
                ea = self.parse_number(ea)
                func = self.bv.get_function_at(ea)
                if not func:
                    func = self.bv.create_user_function(ea)
                if func:
                    func.name = f"{class_name}.{func_name}"

        if "vtbls" in data and data["vtbls"]:
            i = 0
            for vtbl in data["vtbls"]:
                vtbl_type_name = f"{class_name}::vtable"
                if i > 0:
                    vtbl_type_name += f"_{i}"

                ea = vtbl["ea"]
                ea = self.parse_number(ea)
                vtbl_type = self.void_ptr

                existing_vtbl_type = self.bv.get_type_by_name(vtbl_type_name)
                if existing_vtbl_type:
                    vtbl_type = existing_vtbl_type.mutable_copy()

                if "vfuncs" in data and data["vfuncs"]:
                    type_builder = TypeBuilder.structure()
                    type_builder.propagate_data_var_refs = True
                    if "base" in data:
                        base_type = self.bv.get_type_by_name(data["base"])
                        if base_type:
                            type_builder.base_structures = [base_type]

                    for idx, name in data["vfuncs"].items():
                        offset = int(idx) * 8

                        func_type = self.void_ptr
                        func_addr = self.bv.read_pointer(ea + offset)
                        func = self.bv.get_function_at(func_addr)
                        if func:
                            func_type = TypeBuilder.pointer(self.bv.arch, func.type)
                            func.name = f"{class_name}.{name}"

                        existing_field = type_builder.member_at_offset(offset)
                        if existing_field:
                            type_builder.remove(offset)
                        type_builder.insert(offset, func_type, name)

                    self.bv.define_user_type(vtbl_type_name, type_builder)
                    vtbl_type = self.bv.get_type_by_name(vtbl_type_name)  # lol wut

                var = self.bv.get_data_var_at(ea)
                if var:
                    var.type = vtbl_type
                    var.name = vtbl_type_name
                else:
                    var = self.bv.define_user_data_var(ea, vtbl_type, vtbl_type_name)


def rename(bv: BinaryView):
    task = Rename(bv)
    task.start()
