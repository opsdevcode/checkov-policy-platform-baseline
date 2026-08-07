from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from repave_policy_utils import read_scanned_resource_file, references_shared_locals


class NullResourceUsesSharedLocals(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Scaffold resources must reference shared locals for naming and tags",
            id="CKV2_REPAVE_7",
            categories=(CheckCategories.CONVENTION,),
            supported_resources=("null_resource",),
            guideline=(
                "Resource files should consume local.name_prefix and local.common_tags "
                "instead of ad hoc var.* usage."
            ),
        )

    def run(self, scanned_file, entity_configuration, entity_name, entity_type, skip_info):
        self._scanned_file = scanned_file
        return super().run(scanned_file, entity_configuration, entity_name, entity_type, skip_info)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        content = read_scanned_resource_file(getattr(self, "_scanned_file", ""))
        if content is None:
            return CheckResult.FAILED
        if not references_shared_locals(content):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = NullResourceUsesSharedLocals()
