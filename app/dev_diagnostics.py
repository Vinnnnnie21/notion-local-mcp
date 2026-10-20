"""只返回规则、位置和操作信息，不包含文件内容或宿主绝对路径。"""
import re
import secrets
from pathlib import PurePosixPath


class DevelopmentDenied(ValueError):
    def __init__(self, message, rule_id, path=None, file_category='task_file', **location):
        super().__init__(message)
        self.diagnostic = {
            'error_code': 'development_security_denied', 'rule_id': rule_id,
            'operation': 'validation', 'workspace_id': None, 'phase': 'preflight',
            'file_category': file_category, 'diagnostic_id': secrets.token_hex(12),
        }
        if path is not None:
            p = PurePosixPath(str(path))
            if not p.is_absolute() and '..' not in p.parts and re.fullmatch(r'[A-Za-z0-9_./-]{1,250}', str(p)):
                self.diagnostic['path'] = str(p)
            else:
                self.diagnostic['file_category'] = 'restricted_path'
        self.diagnostic.update(location)

    def contextualize(self, workspace_id, operation, phase):
        self.diagnostic.update(workspace_id=workspace_id, operation=operation, phase=phase)
        return self


def application_status(result):
    if not isinstance(result, dict):
        return 'ok'
    if result.get('applied') is False or result.get('restored') is False:
        rows = result.get('results', [])
        return 'partial_failure' if any(row.get('applied') or row.get('restored') for row in rows) else 'not_applied'
    if result.get('status') in {'blocked', 'failed', 'unknown', 'timeout', 'termination_failed'}:
        return result['status']
    return 'ok'


def diagnostic_for(error, workspace_id, operation, phase):
    if isinstance(error, DevelopmentDenied):
        return error.contextualize(workspace_id, operation, phase).diagnostic
    rule = 'filesystem.permission' if isinstance(error, PermissionError) else 'workspace.validation'
    return DevelopmentDenied('Workspace validation failed', rule, file_category='restricted_path').contextualize(
        workspace_id, operation, phase).diagnostic
