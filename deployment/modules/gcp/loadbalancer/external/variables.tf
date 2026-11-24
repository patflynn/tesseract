variable "project_id" {
  description = "GCP project ID where the log is hosted."
  type        = string
}

variable "logs" {
  description = "Map of log names to regions."
  type = map(object({
    // Region in which the backends are
    region = string
    // origin = [basename].[submission_host_suffix]
    submission_host_suffix = string
    // Backend type: "mig" (default), "dual" (side-by-side MIG + Cloud Run NEG), or "cloudrun".
    backend_type = optional(string, "mig")
    // When backend_type == "dual", routes submission traffic to the Cloud Run NEG backend if true.
    route_to_cloudrun = optional(bool, false)
    // Optional Cloud Run region override (defaults to region) so changing Cloud Run region does not rotate SSL certs.
    cloudrun_region = optional(string)
    // Optional Cloud Run service name override (defaults to the log map key).
    cloudrun_service_name = optional(string)
  }))

  validation {
    condition = alltrue([
      for name, v in var.logs : v.region != "" && v.submission_host_suffix != "" && !startswith(v.submission_host_suffix, ".")
    ])
    error_message = "Both the region and submission_host_suffix must be set for each log. submission_host_suffix must not start with a \".\""
  }

  validation {
    condition = alltrue([
      for name, v in var.logs : contains(["mig", "dual", "cloudrun"], v.backend_type) && (v.backend_type != "mig" || !v.route_to_cloudrun)
    ])
    error_message = "backend_type must be \"mig\", \"dual\", or \"cloudrun\", and route_to_cloudrun cannot be true when backend_type is \"mig\"."
  }
}

variable "enable_cloud_armor" {
  description = "Whether or not to enable Cloud Armor for the load balancer."
  type        = bool
  default     = false
}
