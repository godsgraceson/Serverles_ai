from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


SERVICE_ACTIONS = {
    "s3": ["s3:GetObject"],
    "sqs": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
    "dynamodb": ["dynamodb:GetItem", "dynamodb:PutItem"],
    "secretsmanager": ["secretsmanager:GetSecretValue"],
    "ssm": ["ssm:GetParameter"],
    "lambda": ["lambda:InvokeFunction"],
}


@dataclass
class PolicyBundle:
    aws: dict
    azure_rbac: list[str]
    gcp_roles: list[str]
    findings: list[str]


class _CallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.services: set[str] = set()
        self.findings: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = ""
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        if name in {"client", "resource"} and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                self.services.add(arg0.value.lower())
        if name in {"Popen", "system", "call"}:
            self.findings.append("subprocess usage detected; deny shell in production IAM/runtime")
        self.generic_visit(node)


def generate_least_privilege_policy(source_path: str | Path) -> PolicyBundle:
    """Static analysis of function code → minimal cloud permission sets."""
    tree = ast.parse(Path(source_path).read_text())
    visitor = _CallVisitor()
    visitor.visit(tree)
    actions: list[str] = []
    azure: list[str] = []
    gcp: list[str] = []
    for service in sorted(visitor.services):
        actions.extend(SERVICE_ACTIONS.get(service, [f"{service}:Describe*"]))
        if service == "s3":
            azure.append("Storage Blob Data Reader")
            gcp.append("roles/storage.objectViewer")
        elif service == "secretsmanager":
            azure.append("Key Vault Secrets User")
            gcp.append("roles/secretmanager.secretAccessor")
    if not actions:
        actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
        azure.append("Monitoring Metrics Publisher")
        gcp.append("roles/logging.logWriter")
    aws = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SASLeastPrivilege",
                "Effect": "Allow",
                "Action": sorted(set(actions)),
                "Resource": "*",
                "Condition": {"NumericLessThanEquals": {"aws:RequestedRegionCount": 1}},
            }
        ],
    }
    return PolicyBundle(aws=aws, azure_rbac=azure, gcp_roles=gcp, findings=visitor.findings)
