data "aws_iam_policy_document" "ecs_tasks_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

locals {
  ssm_secret_arns = distinct([for v in values(var.secrets) : v if startswith(v, "arn:aws:ssm:")])
  # A Secrets Manager valueFrom may carry a :json-key:version-stage:version-id
  # suffix; the IAM resource is the secret ARN (first seven fields) plus a wildcard
  # for the random suffix Secrets Manager appends.
  sm_secret_arns = distinct([for v in values(var.secrets) : "${join(":", slice(split(":", v), 0, 7))}*" if startswith(v, "arn:aws:secretsmanager:")])
}

# ------------------------------------------------------------------ execution role
resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_secrets" {
  dynamic "statement" {
    for_each = length(local.ssm_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadSsmSecrets"
      actions   = ["ssm:GetParameters"]
      resources = local.ssm_secret_arns
    }
  }
  dynamic "statement" {
    for_each = length(local.sm_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadSecretsManager"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.sm_secret_arns
    }
  }
  statement {
    sid       = "DecryptViaSsmAndSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "ssm.${data.aws_region.current.name}.amazonaws.com",
        "secretsmanager.${data.aws_region.current.name}.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  for_each = length(var.secrets) > 0 ? toset(["this"]) : toset([])
  name     = "secrets"
  role     = aws_iam_role.execution.id
  policy   = data.aws_iam_policy_document.execution_secrets.json
}

# ------------------------------------------------------------------ task role
resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "task" {
  for_each = var.task_role_policies
  name     = each.key
  role     = aws_iam_role.task.id
  policy   = each.value
}

data "aws_iam_policy_document" "exec" {
  statement {
    sid = "EcsExec"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "exec" {
  for_each = var.enable_execute_command ? toset(["this"]) : toset([])
  name     = "ecs-exec"
  role     = aws_iam_role.task.id
  policy   = data.aws_iam_policy_document.exec.json
}
