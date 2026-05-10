# Azure-Sentinel-SIEM-Lab
Laboratorio SIEM con Microsoft Sentinel en Azure — detección de amenazas, KQL y análisis de eventos de seguridad


# 🛡️ Laboratorio SIEM — Microsoft Sentinel en Azure

**Analista:** Julián Amell Romero  
**Fecha:** Abril 2026  
**Tecnologías:** Microsoft Sentinel · Log Analytics · Azure Monitor Agent · KQL · Windows Server 2022 · Active Directory

---

## 🎯 Objetivo

Desplegar un SIEM real en Azure y detectar eventos de seguridad en infraestructura Windows mediante Microsoft Sentinel y consultas KQL.

---

## 🏗️ Infraestructura desplegada

- 2 VMs en Azure (Windows Server 2022) con Active Directory
- Log Analytics Workspace conectado a Microsoft Sentinel
- Azure Monitor Agent (AMA) instalado en ambos servidores
- Conector de Windows Security Events activo

---

## 🔍 Escenarios de detección implementados

### Escenario 1 — Login fallido con usuario inexistente (Event ID 4625)
**Descripción:** Se intentó iniciar sesión con la cuenta `joker` (inexistente).  
**Detectado:** 7/04/2026 — 3:02 AM  
**Gravedad:** Baja (1 intento) → Alta si fueran cientos  

```kql
SecurityEvent
| where EventID == 4625
| where Account has "joker"
| project TimeGenerated, Computer, Account, IpAddress, Status
```

---

### Escenario 2 — Sesión RDP remota (LogonType 10 / Event ID 4624)
**Descripción:** Detección de acceso remoto por escritorio (RDP) a un servidor.  

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Computer, Account, IpAddress, LogonTypeName = "RDP"
```

---

### Escenario 3 — Creación de cuenta sospechosa post-compromiso
**Descripción:** Simulación de atacante que crea una cuenta nueva para mantener persistencia.  
**Objetivo:** Detectar qué cuenta fue creada y quién la creó.

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, Account, SubjectAccount = SubjectUserName
```

---

## 🧰 Stack tecnológico

| Componente | Tecnología |
|-----------|-----------|
| SIEM | Microsoft Sentinel |
| Cloud | Microsoft Azure |
| SO | Windows Server 2022 |
| Directorio | Active Directory DS |
| Agente | Azure Monitor Agent (AMA) |
| Lenguaje de consulta | KQL (Kusto Query Language) |

---

## 🔗 Laboratorio relacionado

👉 [Azure AD Identity Lab](https://github.com/julianamell2/Azure-AD-Identity-Lab) — Infraestructura híbrida AD + Entra Connect
