terraform {
  required_version = ">= 1.5.0"
}

variable "model_hash" {
  type        = string
  description = "SHA-256 of the signed model artifact"
}

output "sas_env" {
  value = {
    SAS_EXPECTED_MODEL_HASH  = var.model_hash
    SAS_RETURN_CONFIDENCE    = "false"
    SAS_EXTRACTION_THRESHOLD = "40"
  }
}
