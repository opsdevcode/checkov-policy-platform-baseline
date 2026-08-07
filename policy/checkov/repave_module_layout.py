from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from repave_policy_utils import (
    common_tags_include_allocation_tags,
    declared_variable_names,
    file_contains_resource_blocks,
    module_dir,
    read_module_file,
)


class _RepaveModuleLayoutCheck(BaseResourceCheck):
    """Run module-layout checks once per repository root."""

    _completed_modules: ClassVar[dict[str, set[str]]] = {}

    def __init__(
        self,
        *,
        check_id: str,
        name: str,
        guideline: str,
    ) -> None:
        super().__init__(
            name=name,
            id=check_id,
            categories=(CheckCategories.CONVENTION,),
            supported_resources=("null_resource",),
            guideline=guideline,
        )

    def _module_root(self) -> Path:
        scanned_file = getattr(self, "_scanned_file", "")
        return module_dir(scanned_file)

    def _run_once(self, module_key: str) -> bool:
        seen = self._completed_modules.setdefault(self.id, set())
        if module_key in seen:
            return False
        seen.add(module_key)
        return True

    def run(self, scanned_file, entity_configuration, entity_name, entity_type, skip_info):
        self._scanned_file = scanned_file
        return super().run(scanned_file, entity_configuration, entity_name, entity_type, skip_info)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        module_key = str(self._module_root())
        if not self._run_once(module_key):
            return CheckResult.PASSED
        return self.scan_module_layout(self._module_root())

    def scan_module_layout(self, module_root: Path) -> CheckResult:
        raise NotImplementedError


class LocalsFilePresent(_RepaveModuleLayoutCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_3",
            name="Module must include locals.tf for shared derived values",
            guideline="Place shared tags, naming, and scope maps in locals.tf per the module standard.",
        )

    def scan_module_layout(self, module_root: Path) -> CheckResult:
        if read_module_file(module_root, "locals.tf") is None:
            return CheckResult.FAILED
        return CheckResult.PASSED


class VariablesFileHasNoResources(_RepaveModuleLayoutCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_4",
            name="variables.tf must not declare resource blocks",
            guideline="Keep inputs in variables.tf; declare infrastructure in dedicated resource files.",
        )

    def scan_module_layout(self, module_root: Path) -> CheckResult:
        content = read_module_file(module_root, "variables.tf")
        if content is None:
            return CheckResult.FAILED
        if file_contains_resource_blocks(content):
            return CheckResult.FAILED
        return CheckResult.PASSED


class MainTfHasNoResources(_RepaveModuleLayoutCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_5",
            name="main.tf must not contain standalone resource blocks",
            guideline="Use one {service}_{resource}.tf file per resource instead of a monolithic main.tf.",
        )

    def scan_module_layout(self, module_root: Path) -> CheckResult:
        content = read_module_file(module_root, "main.tf")
        if content is None:
            return CheckResult.PASSED
        if file_contains_resource_blocks(content):
            return CheckResult.FAILED
        return CheckResult.PASSED


class RequiredModuleVariables(_RepaveModuleLayoutCheck):
    REQUIRED = ("environment", "tags")

    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_6",
            name="Module must declare environment and tags input variables",
            guideline="Accept environment and tags at the module boundary for consistent tagging.",
        )

    def scan_module_layout(self, module_root: Path) -> CheckResult:
        declared = declared_variable_names(module_root)
        missing = [name for name in self.REQUIRED if name not in declared]
        if missing:
            return CheckResult.FAILED
        return CheckResult.PASSED


class AllocationTagsInCommonLocals(_RepaveModuleLayoutCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_13",
            name="locals.tf common_tags must include FinOps allocation tags",
            guideline=(
                "Merge Owner, Service, Environment, and CostCenter into local.common_tags "
                "from module inputs (var.owner, var.service, var.environment, var.cost_center)."
            ),
        )

    def scan_module_layout(self, module_root: Path) -> CheckResult:
        content = read_module_file(module_root, "locals.tf")
        if content is None:
            return CheckResult.FAILED
        if not common_tags_include_allocation_tags(content):
            return CheckResult.FAILED
        return CheckResult.PASSED


check_locals_file_present = LocalsFilePresent()
check_variables_file_has_no_resources = VariablesFileHasNoResources()
check_main_tf_has_no_resources = MainTfHasNoResources()
check_required_module_variables = RequiredModuleVariables()
check_allocation_tags_in_common_locals = AllocationTagsInCommonLocals()
