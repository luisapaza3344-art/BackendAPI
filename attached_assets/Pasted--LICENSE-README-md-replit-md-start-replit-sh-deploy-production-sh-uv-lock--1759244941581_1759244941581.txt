.
├── LICENSE
├── README.md
├── replit.md
├── start-replit.sh
├── deploy-production.sh
├── uv.lock
├── package.json
├── package-lock.json
├── pyproject.toml
├── flake.nix                          # Entorno de desarrollo reproducible (opcional pero recomendado)

# 👇 Documentación viva y decisiones arquitectónicas
├── docs/
│   ├── adr/                           # Architecture Decision Records
│   ├── compliance/                    # Mapeo a PCI DSS, GDPR, NIST PQC
│   ├── threat-models/
│   └── runbooks/

# 👇 Activos seguros (renombrado y organizado)
├── assets/
│   └── security-briefs/
│       └── CISO-security-team-brief.txt

# 👇 Aplicaciones frontend (con roles diferenciados)
├── apps/
│   ├── store/                         # Para compradores: sin 2FA obligatorio
│   │   ├── public/
│   │   ├── src/
│   │   │   ├── services/
│   │   │   │   ├── auth.service.ts    # Usa /api/auth/login (tu servicio auth)
│   │   │   │   └── payment.service.ts
│   │   │   └── ...
│   │   └── ...
│   │
│   ├── merchant-portal/               # Para vendedores: 2FA obligatorio
│   │   ├── src/
│   │   │   ├── services/
│   │   │   │   ├── auth.service.ts    # Usa /api/auth/login + /api/auth/2fa (tu auth)
│   │   │   │   └── dashboard.service.ts
│   │   │   └── ...
│   │   └── ...
│   │
│   └── admin-console/                 # Interno: 2FA + mTLS
│       └── ...

# 👇 Servicios backend (dominios claros, sin mezclar lenguajes)
├── services/
│   ├── auth/                          # 🔒 TU CARPETA AUTH — SIN CAMBIOS
│   │   ├── cmd/
│   │   ├── db/migrations/
│   │   ├── go.mod
│   │   ├── go.sum
│   │   └── internal/
│   │       ├── app/
│   │       ├── config/
│   │       ├── database/
│   │       ├── did/                   # (puedes dejarlo o eliminarlo; no lo usamos)
│   │       ├── handlers/
│   │       ├── logger/
│   │       ├── middleware/
│   │       └── webauthn/
│   │
│   ├── payments/                      # Gateway de pagos (PCI DSS Scope)
│   │   ├── src/                       # Rust (como tenías)
│   │   ├── migrations/
│   │   └── Cargo.toml
│   │
│   ├── fraud/                         # Detección de fraude
│   │   ├── python/
│   │   └── models/
│   │
│   ├── rbac/                          # Control de acceso por rol
│   │   └── go/
│   │
│   ├── attestation/                   # Attestation de integridad
│   │   └── go/
│   │
│   ├── messaging/                     # Cola de mensajes
│   │   └── python/
│   │
│   └── shipping/                      # Gestión de envíos
│       └── rust/

# 👇 Núcleo compartido post-cuántico (seguro, verificado, reutilizable)
├── shared/
│   └── crypto-pqc/
│       ├── go/                        # Librería Go con OQS + modos híbridos
│       ├── rust/                      # Crate con pqcrypto
│       └── typescript/                # Para frontend (WebCrypto + fallback)

# 👇 Infraestructura como código (GitOps-first)
├── infra/
│   ├── aws/
│   │   └── modules/
│   ├── k8s/
│   │   └── charts/
│   └── policy/                        # OPA, Kyverno, políticas de red

# 👇 Observabilidad segura
├── observability/
│   ├── grafana/dashboards/
│   ├── loki/configurations/
│   └── prometheus/rules/

# 👇 Cumplimiento y seguridad
├── compliance/
│   ├── evidence/                      # Para auditores
│   └── scanners/                      # Configuración de escáneres

# 👇 Pruebas (por dominio y tipo)
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── security/                      # Pruebas de penetración
│   └── quantum/                       # Simulación de amenazas cuánticas

# 👇 Herramientas y scripts
├── tools/
│   ├── pq-migrator/
│   └── key-rotator/

# 👇 Configuración global (segura)
├── config/
│   ├── base/
│   └── environments/

# 👇 Archivos raíz esenciales
├── .gitignore
├── .dockerignore
├── Taskfile.yml
└── .sovereign.lock                    # Lista de dependencias permitidas (con algoritmos PQC)