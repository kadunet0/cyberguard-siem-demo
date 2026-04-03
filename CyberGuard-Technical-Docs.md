# CyberGuard SIEM + SOAR Platform
## Documentação Técnica Completa — v3.1.0

---

## 1. Visão Geral da Arquitetura

CyberGuard é uma plataforma corporativa de cibersegurança baseada em microserviços, desenhada para operar como um SIEM (Security Information and Event Management) + SOAR (Security Orchestration, Automation and Response) de alto desempenho. Suporta multi-tenant, RBAC granular e integração nativa com frameworks como MITRE ATT&CK.

---

## 2. Stack Tecnológica

### Frontend
| Componente | Tecnologia |
|---|---|
| Framework | React 18 + TypeScript |
| State | Zustand + React Query |
| Charts | Recharts + D3.js |
| Real-time | WebSocket (Socket.io) |
| GraphQL | Apollo Client |
| Styling | Tailwind CSS + CSS Variables |
| Build | Vite |
| Tests | Vitest + Playwright |

### Backend — Microserviços
| Serviço | Tecnologia | Porta |
|---|---|---|
| API Gateway | Kong / Traefik | 8080 |
| SIEM Core | NestJS + TypeScript | 3001 |
| Threat Intel | FastAPI + Python | 3002 |
| SOAR Engine | NestJS Workflows | 3003 |
| Vuln Manager | FastAPI | 3004 |
| IAM Service | NestJS + Keycloak | 3005 |
| Notification | NestJS | 3006 |
| Log Collector | Go + Fluent Bit | 3007 |
| AI/ML Service | FastAPI + TensorFlow | 3008 |

### Banco de Dados
| Banco | Uso |
|---|---|
| PostgreSQL 16 | Usuários, alertas, vulnerabilidades, playbooks |
| MongoDB 7 | Logs brutos, eventos SIEM, dados não estruturados |
| Elasticsearch 8 | Busca full-text, analytics, dashboards |
| Redis Cluster | Cache, sessões, rate limiting, pub/sub |

### Mensageria & Streaming
- **Apache Kafka** — event streaming entre microserviços
- **RabbitMQ** — filas de notificação e playbooks
- **Fluent Bit** — coleta e roteamento de logs

### Infraestrutura
- **Kubernetes** — orquestração de containers
- **Docker** — empacotamento e build
- **Istio** — service mesh com mTLS
- **HashiCorp Vault** — gerenciamento de secrets
- **MinIO** — armazenamento de artefatos forenses (S3-compatible)

### Observabilidade
- **Prometheus** — coleta de métricas
- **Grafana** — dashboards de observabilidade
- **Jaeger** — distributed tracing
- **ELK Stack** — logs centralizados

---

## 3. Estrutura do Monorepo

```
cyberguard/
├── apps/
│   ├── frontend/              # React + TypeScript
│   │   ├── src/
│   │   │   ├── components/
│   │   │   │   ├── Dashboard/
│   │   │   │   ├── AlertsCenter/
│   │   │   │   ├── ThreatMap/
│   │   │   │   ├── SOAR/
│   │   │   │   ├── Vulnerabilities/
│   │   │   │   ├── IAM/
│   │   │   │   └── AIEngine/
│   │   │   ├── hooks/
│   │   │   ├── store/
│   │   │   ├── services/
│   │   │   └── types/
│   │   ├── public/
│   │   ├── Dockerfile
│   │   └── vite.config.ts
│   │
│   ├── siem-core/             # NestJS
│   │   ├── src/
│   │   │   ├── alerts/
│   │   │   ├── events/
│   │   │   ├── rules-engine/
│   │   │   ├── kafka/
│   │   │   └── websocket/
│   │   ├── Dockerfile
│   │   └── package.json
│   │
│   ├── threat-intel/          # FastAPI
│   │   ├── app/
│   │   │   ├── routers/
│   │   │   ├── models/
│   │   │   ├── ml/
│   │   │   │   ├── anomaly_detector.py
│   │   │   │   ├── threat_classifier.py
│   │   │   │   └── behavior_lstm.py
│   │   │   ├── feeds/
│   │   │   │   ├── mitre_attack.py
│   │   │   │   ├── alienvault_otx.py
│   │   │   │   └── virustotal.py
│   │   │   └── utils/
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   │
│   ├── soar-engine/           # NestJS
│   │   ├── src/
│   │   │   ├── playbooks/
│   │   │   ├── workflows/
│   │   │   ├── actions/
│   │   │   │   ├── block-ip.action.ts
│   │   │   │   ├── disable-user.action.ts
│   │   │   │   ├── isolate-host.action.ts
│   │   │   │   └── notify.action.ts
│   │   │   └── triggers/
│   │   └── Dockerfile
│   │
│   ├── vuln-manager/          # FastAPI
│   ├── iam-service/           # NestJS + Keycloak
│   ├── notification-service/  # NestJS
│   ├── log-collector/         # Go
│   └── ml-service/            # FastAPI + TensorFlow
│
├── packages/
│   ├── shared-types/          # TypeScript types compartilhadas
│   ├── proto/                 # Protocol Buffers (gRPC)
│   └── ui-kit/                # Componentes React compartilhados
│
├── infrastructure/
│   ├── k8s/                   # Kubernetes manifests
│   │   ├── namespaces/
│   │   ├── deployments/
│   │   ├── services/
│   │   ├── ingress/
│   │   └── hpa/
│   ├── helm/                  # Helm charts
│   ├── terraform/             # IaC para cloud
│   └── docker-compose.yml     # Desenvolvimento local
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── cd-staging.yml
│       └── cd-production.yml
│
├── docs/
│   ├── api/
│   ├── architecture/
│   └── runbooks/
│
└── package.json               # Workspace root (pnpm)
```

---

## 4. API REST — Referência Completa

### Base URL
```
https://api.cyberguard.corp/api/v1
```

### Autenticação
Todos os endpoints requerem `Authorization: Bearer <JWT>`.

---

### 4.1 Alertas

#### `GET /alerts`
Lista alertas com paginação e filtros.

**Query Params:**
| Param | Tipo | Descrição |
|---|---|---|
| `page` | int | Página (default: 1) |
| `limit` | int | Itens por página (max: 100) |
| `severity` | string | CRITICAL, HIGH, MEDIUM, LOW |
| `status` | string | OPEN, ACKNOWLEDGED, CLOSED |
| `from` | ISO8601 | Data de início |
| `to` | ISO8601 | Data de fim |
| `tenant_id` | uuid | Filtro por tenant |

**Response 200:**
```json
{
  "status": "ok",
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 1247,
    "pages": 63
  },
  "data": [
    {
      "id": "ALT-00001",
      "severity": "CRITICAL",
      "message": "Brute-force SSH detectado",
      "source_ip": "185.220.101.45",
      "destination": "10.0.1.20",
      "protocol": "TCP/22",
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "mitre_sub_technique": "T1110.001",
      "status": "OPEN",
      "timestamp": "2025-04-03T14:52:11Z",
      "tenant_id": "corp-001",
      "playbook_triggered": "block-ip-v1",
      "enrichment": {
        "geo_country": "Russia",
        "geo_city": "Moscow",
        "asn": "AS60068",
        "reputation_score": 97,
        "threat_feeds": ["AbuseIPDB", "Shodan", "AlienVault"]
      }
    }
  ]
}
```

#### `POST /alerts`
Criar alerta manual.

```json
{
  "severity": "HIGH",
  "message": "Acesso suspeito detectado manualmente",
  "source_ip": "10.0.5.22",
  "destination": "fileserver01",
  "mitre_tactic": "Collection"
}
```

#### `PATCH /alerts/:id/ack`
Reconhecer alerta.

#### `PATCH /alerts/:id/close`
Fechar alerta com resolução.

```json
{
  "resolution": "false_positive",
  "notes": "Verificado com equipe de infra — acesso legítimo"
}
```

---

### 4.2 Playbooks SOAR

#### `GET /playbooks`
Lista playbooks disponíveis.

#### `POST /playbooks/:id/execute`
Executa um playbook manualmente.

**Request:**
```json
{
  "trigger_data": {
    "source_ip": "185.220.101.45",
    "alert_id": "ALT-00001"
  },
  "dry_run": false
}
```

**Response 202:**
```json
{
  "execution_id": "EXEC-7f3a2b",
  "playbook_id": "block-ip-v1",
  "status": "RUNNING",
  "started_at": "2025-04-03T14:55:00Z",
  "steps": [
    { "name": "Adicionar IP à blocklist", "status": "COMPLETED" },
    { "name": "Notificar SOC via Slack", "status": "RUNNING" },
    { "name": "Criar ticket JIRA", "status": "PENDING" }
  ]
}
```

---

### 4.3 Vulnerabilidades

#### `GET /vulnerabilities`
Lista CVEs detectadas.

#### `POST /scan/start`
Inicia scan de vulnerabilidades.

```json
{
  "targets": ["10.0.0.0/24", "10.0.1.0/24"],
  "profile": "full",
  "scanner": "internal"
}
```

---

### 4.4 Threat Intelligence

#### `GET /intel/feeds`
Lista feeds de threat intelligence ativos.

#### `POST /intel/lookup`
Consulta reputação de um IOC (IP, hash, domínio).

```json
{
  "type": "ip",
  "value": "185.220.101.45"
}
```

**Response:**
```json
{
  "ioc": "185.220.101.45",
  "type": "ip",
  "reputation_score": 97,
  "threat_level": "CRITICAL",
  "categories": ["brute_force", "tor_exit_node", "c2_server"],
  "geo": { "country": "RU", "city": "Moscow" },
  "feeds": {
    "AbuseIPDB": { "confidence": 100, "reports": 3421 },
    "AlienVault": { "pulses": 14 },
    "Shodan": { "ports": [22, 443, 8080] }
  },
  "mitre_techniques": ["T1110", "T1059"]
}
```

---

### 4.5 Métricas

#### `GET /metrics/summary`
```json
{
  "period": "24h",
  "events_processed": 18243,
  "alerts_generated": 127,
  "threats_active": 12,
  "connections_blocked": 4821,
  "security_score": 67,
  "mttr_minutes": 4.4,
  "soar_executions": 89
}
```

---

### 4.6 Webhooks

#### `POST /webhooks`
Registrar webhook.

```json
{
  "name": "SOC Slack Channel",
  "url": "https://hooks.slack.com/services/...",
  "events": ["alert.created", "alert.critical", "playbook.executed"],
  "severity_filter": ["CRITICAL", "HIGH"],
  "secret": "whsec_..."
}
```

---

## 5. Modelos de Machine Learning

### 5.1 AnomalyNet (Autoencoder)
- **Tipo:** Autoencoder LSTM para detecção de anomalias em séries temporais
- **Input:** 48 features de comportamento de rede (volume, frequência, padrões de protocolo)
- **Output:** Anomaly score [0–1], threshold configurável (default: 0.85)
- **Acurácia:** 97.4% | Falso Positivo: 0.8%
- **Retreino:** Contínuo, ciclo de 24h com novos dados

### 5.2 ThreatClassifier (XGBoost)
- **Tipo:** Classificação multi-classe
- **Classes:** 12 táticas MITRE ATT&CK
- **Features:** 156 features extraídas de logs (IP reputation, frequency, timing, payload)
- **Acurácia:** 94.1% | Falso Positivo: 2.1%

### 5.3 BehaviorLSTM (Staging)
- **Tipo:** LSTM para análise comportamental de usuários (UEBA)
- **Input:** Sequência de ações por usuário (últimas 100 ações)
- **Output:** Risk score + desvio do baseline
- **Status:** Staging — validação em andamento

---

## 6. CI/CD — GitHub Actions

### Pipeline de CI (`ci.yml`)

```yaml
name: CI Pipeline
on: [push, pull_request]

jobs:
  test-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v3
      - run: pnpm install --frozen-lockfile
      - run: pnpm --filter frontend test
      - run: pnpm --filter frontend build

  test-backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env: { POSTGRES_DB: cyberguard_test, POSTGRES_PASSWORD: test }
      redis:
        image: redis:7
    steps:
      - uses: actions/checkout@v4
      - run: pnpm --filter siem-core test
      - run: pnpm --filter soar-engine test

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: SAST — Semgrep
        uses: returntocorp/semgrep-action@v1
      - name: Dependency audit
        run: pnpm audit --audit-level=high
      - name: Container scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: CRITICAL,HIGH

  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker compose up -d
      - run: pnpm --filter frontend e2e
```

### Pipeline de CD — Produção (`cd-production.yml`)

```yaml
name: Deploy Production
on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - name: Build & push Docker images
        run: |
          docker build -t cyberguard/siem-core:${{ github.sha }} apps/siem-core
          docker push cyberguard/siem-core:${{ github.sha }}

      - name: Deploy to Kubernetes
        uses: azure/k8s-deploy@v4
        with:
          manifests: infrastructure/k8s/deployments/
          images: cyberguard/siem-core:${{ github.sha }}

      - name: Run smoke tests
        run: ./scripts/smoke-test.sh

      - name: Notify Slack
        uses: slackapi/slack-github-action@v1
```

---

## 7. Kubernetes — Deploy

### Deployment Principal (SIEM Core)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: siem-core
  namespace: cyberguard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: siem-core
  template:
    spec:
      containers:
      - name: siem-core
        image: cyberguard/siem-core:latest
        ports:
        - containerPort: 3001
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: cyberguard-secrets
              key: database-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 3001
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: siem-core-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: siem-core
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

---

## 8. Segurança do Sistema

### 8.1 Criptografia
- Dados em repouso: **AES-256-GCM** via HashiCorp Vault
- Dados em trânsito: **TLS 1.3** obrigatório
- Senhas: **Argon2id** com salt por usuário
- Tokens JWT: **RS256** (RSA 2048-bit), expiração 15min
- Refresh tokens: **RS256**, expiração 7 dias, rotação automática

### 8.2 Proteções de API
- **Rate limiting:** Redis sliding window (100 req/min por IP, 1000 req/min por token)
- **CSRF:** Double-submit cookie pattern
- **SQL Injection:** Parameterized queries via TypeORM + Prisma
- **XSS:** Content-Security-Policy headers, sanitização de output
- **DDoS:** Traefik rate limiting + Cloudflare WAF
- **Input validation:** class-validator (NestJS) + Pydantic (FastAPI)

### 8.3 Políticas de Segurança Kubernetes
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: siem-core-netpol
spec:
  podSelector:
    matchLabels:
      app: siem-core
  policyTypes: [Ingress, Egress]
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - port: 3001
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - port: 5432
```

---

## 9. Multi-Tenant

O sistema suporta isolamento completo por tenant:

- **Dados:** Cada tenant possui schema PostgreSQL isolado
- **Eventos:** Particionamento por `tenant_id` no Kafka
- **Autenticação:** Realm separado por tenant no Keycloak
- **RBAC:** Permissões são sempre escopadas por `tenant_id`
- **API:** Middleware de tenant extrai `X-Tenant-ID` do JWT

---

## 10. Coleta de Logs — Protocolos

### Syslog (RFC 5424)
```
Porta UDP/TCP: 514 (plain), 6514 (TLS)
Formato: <priority>version timestamp hostname app-name procid msgid msg
```

### SNMP Traps
```
Porta UDP: 162
Versões: SNMPv2c, SNMPv3 (authPriv)
Community: configurável por source
```

### API Push (REST)
```
POST /api/v1/ingest/events
Content-Type: application/json
Authorization: Bearer <token>

{
  "source": "nginx-prod-01",
  "type": "access_log",
  "events": [{ "timestamp": "...", "level": "WARN", "message": "..." }]
}
```

### Agente (CyberGuard Agent)
- Binário Go leve (~8MB)
- Suporte Windows, Linux, macOS
- Coleta: logs de aplicação, eventos de sistema, EDR hooks
- Comunicação: gRPC + mTLS

---

## 11. Exemplos de Uso da API

### Listar alertas críticos das últimas 24h
```bash
curl -X GET \
  "https://api.cyberguard.corp/api/v1/alerts?severity=CRITICAL&from=2025-04-02T00:00:00Z&status=OPEN" \
  -H "Authorization: Bearer $TOKEN"
```

### Executar playbook de isolamento
```bash
curl -X POST \
  "https://api.cyberguard.corp/api/v1/playbooks/isolate-endpoint/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"trigger_data": {"host": "10.0.2.78", "alert_id": "ALT-00010"}}'
```

### Consultar reputação de IP
```bash
curl -X POST \
  "https://api.cyberguard.corp/api/v1/intel/lookup" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type": "ip", "value": "185.220.101.45"}'
```

### Exportar relatório CSV
```bash
curl -X GET \
  "https://api.cyberguard.corp/api/v1/export?format=csv&type=vulnerabilities&from=2025-04-01" \
  -H "Authorization: Bearer $TOKEN" \
  --output vulnerabilities-report.csv
```

---

## 12. Glossário

| Termo | Significado |
|---|---|
| SIEM | Security Information and Event Management |
| SOAR | Security Orchestration, Automation and Response |
| IOC | Indicator of Compromise |
| TTP | Tactics, Techniques and Procedures |
| CVSS | Common Vulnerability Scoring System |
| RBAC | Role-Based Access Control |
| MTTR | Mean Time to Respond |
| UEBA | User and Entity Behavior Analytics |
| EDR | Endpoint Detection and Response |
| SOC | Security Operations Center |

---

*CyberGuard Platform — Documentação Técnica v3.1.0 — Abril 2025*
