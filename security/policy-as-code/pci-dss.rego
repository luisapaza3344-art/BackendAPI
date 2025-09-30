# PCI-DSS Level 1 Compliance Policies for Government Platform
package gov.platform.pci

import future.keywords.if
import future.keywords.in

# Requirement 2.2: Secure configuration standards
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("PCI-DSS 2.2: Container %s must not run privileged", [container.name])
}

# Requirement 2.3: Encrypt all non-console administrative access
deny[msg] {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    not input.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-cert"]
    msg := "PCI-DSS 2.3: LoadBalancer must use TLS encryption"
}

# Requirement 3.4: Render PAN unreadable (encryption at rest)
deny[msg] {
    input.kind == "PersistentVolumeClaim"
    not input.metadata.annotations["encrypted"]
    msg := "PCI-DSS 3.4: All PVCs must be encrypted at rest"
}

# Requirement 4.1: Use strong cryptography for data transmission
deny[msg] {
    input.kind == "Ingress"
    ingress_tls := input.spec.tls[_]
    not contains(input.metadata.annotations["nginx.ingress.kubernetes.io/ssl-protocols"], "TLSv1.3")
    msg := "PCI-DSS 4.1: Ingress must enforce TLS 1.3"
}

# Requirement 6.2: Ensure all system components are protected from known vulnerabilities
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    contains(container.image, ":latest")
    msg := sprintf("PCI-DSS 6.2: Container %s must use pinned image version, not :latest", [container.name])
}

# Requirement 8.2: Multi-factor authentication for all access
deny[msg] {
    input.kind == "ServiceAccount"
    input.metadata.namespace == "gov-platform"
    not input.metadata.annotations["platform.gov/mfa-required"]
    msg := sprintf("PCI-DSS 8.2: ServiceAccount %s must require MFA", [input.metadata.name])
}

# Requirement 10.1: Implement audit trails
deny[msg] {
    input.kind == "Deployment"
    input.metadata.namespace == "gov-platform"
    not input.spec.template.spec.containers[_].volumeMounts[_].name == "audit-logs"
    msg := sprintf("PCI-DSS 10.1: Deployment %s must have audit logging", [input.metadata.name])
}

# Post-Quantum Cryptography Requirements
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.env[_].name == "PQ_CRYPTO_ENABLED"
    msg := sprintf("Gov Standard: Container %s must enable post-quantum cryptography", [container.name])
}

# FIPS 140-3 Level 3 Compliance
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    fips_mode := [env | env := container.env[_]; env.name == "FIPS_MODE"]
    count(fips_mode) == 0
    msg := sprintf("FIPS 140-3: Container %s must enable FIPS mode", [container.name])
}
