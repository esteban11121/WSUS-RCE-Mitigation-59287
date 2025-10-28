# 🚨 ALERTA CRÍTICA DE CIBERSEGURIDAD: RCE en WSUS (CVE-2025-59287) 🚨

**CREADOR Y CRÉDITOS:** (@esteban11121)
*Esta guía ha sido elaborada para ayudar a la comunidad a mitigar rápidamente la vulnerabilidad.*

**ESTADO: Explotación Activa (In-the-Wild) Confirmada.**

Esta es una vulnerabilidad de **Ejecución Remota de Código (RCE)** que afecta a los servidores **WSUS**, permitiendo a atacantes no autenticados obtener privilegios de **SYSTEM**. Se requiere una acción de parcheo **Fuera de Banda (OOB)** inmediata.

| Detalle | Valor |
| :--- | :--- |
| **Identificador** | CVE-2025-59287 |
| **Severidad CVSS** | **9.8 (Crítica)** |
| **Vector de Ataque** | Red (Ejecución remota, no autenticada) |
| **Servicios Afectados** | Windows Server Update Services (WSUS) |
| **Acción Requerida** | Parcheo OOB y Reinicio |

---

## 🎯 ALCANCE: Servidores Vulnerables

**SOLO** los servidores Windows que tengan el **Rol de Servidor WSUS (Windows Server Update Services) HABILITADO** están en riesgo.

| Versión de Windows Server | Estado de la Vulnerabilidad |
| :--- | :--- |
| Server 2025 | **Vulnerable** |
| Server 2022 | **Vulnerable** |
| Server 2019 | **Vulnerable** |
| Server 2016 | **Vulnerable** |
| Server 2012 / 2012 R2 | **Vulnerable** |

---

## 📝 PASO A PASO: Plan de Mitigación y Parcheo Urgente

El objetivo es asegurar los sistemas vulnerables antes de aplicar la actualización OOB.

### FASE I: Identificación y Aislamiento (Acción Inmediata)

1.  **Identificar Servidores:** Confirmar el listado exacto de todos los servidores que ejecutan el Rol de WSUS.

2.  **Mitigación de Emergencia (Si el Parcheo no es instantáneo):**
    * **Opción A (Recomendada):** Bloquear el tráfico **entrante (Inbound)** a los puertos por defecto de WSUS a nivel de Firewall del host o de la red.
        * Puertos a Bloquear: **TCP 8530** (HTTP) y **TCP 8531** (HTTPS).
    * **Opción B:** Deshabilitar temporalmente el Rol/Servicio de Servidor WSUS.

3.  **Verificación:** Confirmar que los puertos 8530/8531 ya no están accesibles desde fuentes no autorizadas.

### FASE II: Preparación y Staging del Parche

1.  **Verificación del SSU (Servicing Stack Update):**
    * **CRÍTICO:** Asegurarse de que el último **Servicing Stack Update (SSU)** aplicable a la versión del SO esté instalado. Un SSU desactualizado puede causar fallos de instalación del parche.

2.  **Descarga de la KB OOB Correcta:**
    * Descargar el paquete OOB (Out-of-Band) desde el **Catálogo de Microsoft Update** utilizando el ID de la KB correspondiente a la versión del servidor.

| Versión de Windows Server | Paquete de Actualización de Seguridad (KB ID) |
| :--- | :--- |
| **Server 2025** | KB5070885 |
| **Server 2022** | **KB5070884** |
| **Server 2019** | **KB5070883** |
| **Server 2016** | **KB5070882** |
| **Server 2012 R2** | **KB5070881** |
| **Server 2012** | **KB5070880** |

### FASE III: Instalación y Verificación Final

1.  **Instalar la KB:** Ejecutar el paquete de actualización de seguridad.
2.  **Reiniciar el Sistema:** La KB es acumulativa y **REQUIERE un REINICIO** para que la mitigación sea efectiva.
3.  **Verificación Post-Parcheo:**
    * Confirmar que la KB se haya instalado correctamente.
    * **IMPORTANTE:** Si se aplicó la Opción A o B de la Fase I, **revertir la mitigación de emergencia** y verificar que el servicio WSUS vuelva a la operación normal.

---

## 🔍 Verificación Adicional del Vector de Ataque

Si necesita confirmar si el componente vulnerable está realmente escuchando y accesible, ejecute este comando en **PowerShell** para verificar los puertos que utiliza el servicio web de WSUS:

```powershell
# Verificación de los puertos de escucha de WSUS (Vector de ataque)
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq 8530 -or $_.LocalPort -eq 8531 }
