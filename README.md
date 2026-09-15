# Repo Vulnerability Miner

CLI en Python para recuperar repositorios de GitHub y analizar hallazgos de
seguridad mediante CodeQL.

## Requisitos

- Python 3.11 o superior.
- Git y CodeQL CLI instalados.
- Un token de GitHub configurado en `GITHUB_TOKEN`.

## Desarrollo

Crear y activar un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instalar el proyecto en modo editable junto con las dependencias de desarrollo:

```bash
python -m pip install -e ".[dev]"
```

Ejecutar las pruebas:

```bash
pytest
```

Comprobar la CLI instalada:

```bash
miner --help
miner --version
```

Configurar el token requerido para las consultas a GitHub:

```bash
export GITHUB_TOKEN="tu-token"
```

Ejecutar un escaneo y guardar el informe JSON:

```bash
miner scan --organization mi-organizacion --output report.json
```

Para limitar la corrida a repositorios concretos, repetir `--repository`:

```bash
miner scan --organization mi-organizacion --output report.json --repository api --repository web
```

El progreso se muestra por stderr; el informe JSON se escribe solo en el archivo
indicado por `--output`. Un repositorio que no pueda analizarse se registra en el
informe y no interrumpe el procesamiento de los demás.

## Reutilización de repositorios

Los clones se conservan por defecto en `.miner/repos/<owner>/<repository>`.
Para elegir otro directorio:

```bash
miner scan --organization mi-organizacion --repos-dir ./results/repos --output ./results/report.json
```

El archivo `<repos-dir>/manifest.json` registra la versión del formato, el
propietario y nombre de cada repositorio, su rama predeterminada al clonarlo,
la ruta relativa del clon y el último commit comprobado. No almacena tokens ni
URLs de autenticación. Los clones y el manifiesto deben conservarse juntos.
Los directorios predeterminados `.miner/` y `results/` están ignorados por Git;
si eliges otra ruta dentro del proyecto, añádela a tu configuración de exclusión.

Al repetir un escaneo, el miner reutiliza los clones registrados y consulta su
HEAD local: **no ejecuta `fetch` ni `pull`**. Para obtener una descarga nueva,
indica un directorio distinto. El escaneo sigue consultando el catálogo de GitHub
y ejecutando CodeQL; este cambio prepara la reutilización para el futuro comando
independiente de SBOM.

Un clon modificado, incompleto o ausente se registra como un fallo del
repositorio. También se rechazan archivos adicionales, incluso los ignorados
por Git, para que el contenido analizado corresponda al commit informado.
El miner no sobrescribe directorios existentes sin registro ni importa clones
manuales. Las bases CodeQL y los SARIF siguen siendo temporales y se eliminan al
cerrar el workspace, también cuando falla el análisis.

Desde Python, `RepositoryWorkspace(repos_directory=Path("..."))` permite leer
el catálogo con `read_manifest()` y abrir un clon mediante
`open_registered(owner, name)` dentro de su contexto `with`, sin consultar GitHub.
El manifiesto admite el uso secuencial; no ejecutes procesos concurrentes sobre
el mismo directorio de clones.

## Modelos de resultados SBOM (preparación de 0.2.0)

El dominio ya permite representar los resultados de Syft con Pydantic. Su
ejecución automática y el comando independiente de SBOM se incorporarán en las
siguientes features; actualmente `scan` sigue ejecutando solamente CodeQL.

En el informe general, cada resultado puede incluir `full_name`
(`owner/repository`) y `sbom`, además del `commit_sha` existente. El campo
`status` del repositorio sigue describiendo CodeQL; `sbom.status` describe Syft.
Por ejemplo, un fallo de CodeQL puede coexistir con un SBOM generado.

El objeto `sbom` contiene:

| Campo | Contrato |
| --- | --- |
| `status` | `generated`, `failed` o `skipped`. |
| `generated_at` | Fecha con zona horaria, normalizada a UTC; solo para un SBOM generado. |
| `syft_version` | Versión de Syft; obligatoria en éxitos y opcional si no se pudo obtener. |
| `component_count` | Entero no negativo; cero es un éxito válido. Solo aparece en éxitos. |
| `path` | Ruta absoluta al CycloneDX JSON original; solo aparece en éxitos. |
| `error` | Etapa y mensaje del fallo o motivo de omisión; obligatorio para `failed` y `skipped`. |

Un resultado `generated` exige fecha, versión, cantidad y ruta, y el repositorio
debe identificar su commit. Un resultado fallido u omitido no admite fecha de
generación, cantidad ni ruta de un artefacto anterior. La versión de Syft y el
commit se conservan cuando están disponibles. El SBOM completo no se incorpora
al informe ni se modifica al serializar sus metadatos.

Ejemplo del objeto `sbom` para un inventario vacío generado correctamente:

```json
{
  "status": "generated",
  "generated_at": "2026-09-15T18:30:00Z",
  "syft_version": "1.0.0",
  "component_count": 0,
  "path": "/reports/example/app.cdx.json"
}
```

`OrganizationScan.summary` conserva los contadores de CodeQL.
`OrganizationScan.sbom_summary` cuenta únicamente los repositorios con un
resultado SBOM: `repositories`, `generated`, `failed`, `skipped` y `components`.
Los informes anteriores, sin `sbom`, se admiten y aportan cero a este resumen;
no se consideran fallidos ni omitidos. `full_name` también es opcional en
resultados antiguos, pero obligatorio cuando hay metadatos SBOM.

Para una corrida independiente, `SbomReport` contiene `organization`,
`repositories` y `summary`. Cada entrada es un `SbomRepositoryResult` con
`full_name`, `commit_sha` cuando se conoce y `sbom`; no exige datos de CodeQL.
Ambos informes usan `write_report_json`, que omite valores ausentes y reemplaza
el archivo atómicamente. Al cargar un informe, los contadores derivados se
recalculan desde los resultados; los demás campos desconocidos se rechazan.

## Autenticación con GitHub

El miner requiere `GITHUB_TOKEN` para todas las consultas a la API de GitHub.
Configúralo en la sesión de terminal antes de ejecutar `miner scan`:

```bash
export GITHUB_TOKEN="tu-token"
```

No guardes el token en archivos versionados, archivos `.env` que vayan a
versionarse ni en la URL de un repositorio.

## Lenguajes soportados

La primera versión habilita análisis CodeQL para JavaScript y TypeScript con la
suite `javascript-security-extended`. El registro de adaptadores permite añadir
otros lenguajes sin modificar el catálogo de GitHub ni la lógica de clonación.
