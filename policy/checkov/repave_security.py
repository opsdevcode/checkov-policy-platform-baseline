from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from repave_policy_utils import (
    file_contains_hardcoded_secrets,
    file_contains_provider_credentials,
    file_contains_provisioners,
    module_tf_contents,
    sensitive_output_names_missing_flag,
)


class _RepaveModuleSecurityCheck(BaseResourceCheck):
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
            categories=(CheckCategories.SECRETS,),
            supported_resources=("null_resource",),
            guideline=guideline,
        )

    def run(self, scanned_file, entity_configuration, entity_name, entity_type, skip_info):
        self._scanned_file = scanned_file
        return super().run(scanned_file, entity_configuration, entity_name, entity_type, skip_info)

    def _module_root(self) -> Path:
        from repave_policy_utils import module_dir

        return module_dir(getattr(self, "_scanned_file", ""))

    def _run_once(self, module_key: str) -> bool:
        seen = self._completed_modules.setdefault(self.id, set())
        if module_key in seen:
            return False
        seen.add(module_key)
        return True

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        module_key = str(self._module_root())
        if not self._run_once(module_key):
            return CheckResult.PASSED
        return self.scan_module_security(self._module_root())

    def scan_module_security(self, module_root: Path) -> CheckResult:
        raise NotImplementedError


class NoProviderCredentialLiterals(_RepaveModuleSecurityCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_8",
            name="Provider blocks must not embed credential literals",
            guideline="Configure provider credentials in root modules or CI secrets, not module code.",
        )

    def scan_module_security(self, module_root: Path) -> CheckResult:
        for content in module_tf_contents(module_root).values():
            if file_contains_provider_credentials(content):
                return CheckResult.FAILED
        return CheckResult.PASSED


class NoHardcodedSecretsInSource(_RepaveModuleSecurityCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_9",
            name="Terraform source must not contain hardcoded secrets",
            guideline="Never commit access keys, tokens, or private key material in .tf files.",
        )

    def scan_module_security(self, module_root: Path) -> CheckResult:
        for content in module_tf_contents(module_root).values():
            if file_contains_hardcoded_secrets(content):
                return CheckResult.FAILED
        return CheckResult.PASSED


class NoProvisioners(_RepaveModuleSecurityCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_10",
            name="Module must not use local-exec or remote-exec provisioners",
            guideline="Prefer native provider resources over imperative provisioners.",
        )

    def scan_module_security(self, module_root: Path) -> CheckResult:
        for content in module_tf_contents(module_root).values():
            if file_contains_provisioners(content):
                return CheckResult.FAILED
        return CheckResult.PASSED


class SensitiveOutputsDeclared(_RepaveModuleSecurityCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_11",
            name="Sensitive outputs must declare sensitive = true",
            guideline="Mark secret-like outputs sensitive to keep them out of logs and state displays.",
        )

    def scan_module_security(self, module_root: Path) -> CheckResult:
        outputs = module_tf_contents(module_root).get("outputs.tf")
        if outputs is None:
            return CheckResult.PASSED
        if sensitive_output_names_missing_flag(outputs):
            return CheckResult.FAILED
        return CheckResult.PASSED


class NoSecretVariableDefaults(_RepaveModuleSecurityCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="CKV2_REPAVE_12",
            name="Variable defaults must not embed secret material",
            guideline="Pass secrets via CI or secret stores; do not default variables to credentials.",
        )

    def scan_module_security(self, module_root: Path) -> CheckResult:
        variables = module_tf_contents(module_root).get("variables.tf")
        if variables is None:
            return CheckResult.PASSED
        if file_contains_hardcoded_secrets(variables):
            return CheckResult.FAILED
        return CheckResult.PASSED


check_no_provider_credential_literals = NoProviderCredentialLiterals()
check_no_hardcoded_secrets_in_source = NoHardcodedSecretsInSource()
check_no_provisioners = NoProvisioners()
check_sensitive_outputs_declared = SensitiveOutputsDeclared()
check_no_secret_variable_defaults = NoSecretVariableDefaults()
