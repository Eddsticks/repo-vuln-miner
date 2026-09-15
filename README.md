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

Ejecutar un escaneo, generar un SBOM CycloneDX JSON por repositorio y guardar el
informe JSON consolidado:

```bash
miner scan --organization mi-organizacion --output report.json
```

Para limitar la corrida a repositorios concretos, repetir `--repository`:

```bash
miner scan --organization mi-organizacion --output report.json --repository api --repository web
```

Para escribir los SBOMs del escaneo en otro directorio, indicar `--sbom-dir`:

```bash
miner scan --organization mi-organizacion --output results/scan.json --sbom-dir results/cyclonedx
```

El progreso se muestra por stderr; el informe JSON se escribe solo en el archivo
indicado por `--output`. Los SBOMs se escriben por defecto en el directorio
`sboms/` junto al informe, con una carpeta única por corrida. Un repositorio que
no pueda analizarse se registra en el informe y no interrumpe el procesamiento de
los demás.

Cada repositorio seleccionado se prepara antes de consultar sus lenguajes y se
procesa con Syft, incluso si no es compatible con CodeQL. El estado de CodeQL y
el de `sbom` son independientes: un SBOM exitoso se conserva si falla CodeQL y
CodeQL continúa si Syft falla. Un fallo al clonar omite el SBOM, pues no hay una
revisión local que inventariar. El resumen final separa hallazgos de CodeQL de
los SBOMs generados, fallidos, omitidos y de su cantidad total de componentes.

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

## Regenerar SBOMs sin CodeQL

El comando `sbom` reutiliza exclusivamente los clones y el manifiesto local.
No requiere `GITHUB_TOKEN`, no consulta GitHub y no ejecuta CodeQL. Para todos
los clones registrados de una organización:

```bash
miner sbom \
  --organization mi-organizacion \
  --repos-dir .miner/repos \
  --output-dir results/regenerated-sboms \
  --output results/sbom-report.json
```

Para regenerar únicamente algunos repositorios, repetir `--repository`:

```bash
miner sbom \
  --organization mi-organizacion \
  --repos-dir .miner/repos \
  --output-dir results/regenerated-sboms \
  --output results/sbom-report.json \
  --repository api --repository web
```

`--organization` se compara con el propietario registrado en el manifiesto y
`--repository` con sus nombres, sin distinguir mayúsculas de minúsculas. Pedir
un repositorio que no está registrado termina el comando antes de generar
archivos. Si no hay clones para esa organización, se escribe un informe válido
con cero repositorios.

El comando abre cada clon registrado, comprueba su commit y estado local, y
genera los CycloneDX JSON en `--output-dir/<run-id>/<owner>/<repository>.cdx.json`.
El informe `--output` es un `SbomReport` independiente: cada entrada contiene
`full_name`, el commit disponible y el estado SBOM; su resumen incluye
`generated`, `failed`, `skipped` y `components`. Un clon dañado o un error de
Syft se registra para ese repositorio y el resto continúa. Los informes y los
SBOMs de corridas anteriores no se modifican.

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

## Ejecutor Syft desde Python

`SyftRunner` genera SBOMs sobre clones locales. `miner scan` lo utiliza
automáticamente y `miner sbom` permite regenerarlos desde los clones persistentes.
Requiere el binario `syft` en el `PATH`; consulta la
[instalación oficial de Syft](https://oss.anchore.com/docs/installation/syft/)
y comprueba que responde con `syft version -o json`.

Ejemplo con un repositorio previamente registrado por el miner:

```python
from pathlib import Path

from repo_vuln_miner.github.workspace import RepositoryWorkspace
from repo_vuln_miner.syft.generation import SyftRunner

runner = SyftRunner(timeout=300.0)
with RepositoryWorkspace(repos_directory=Path(".miner/repos")) as workspace:
    repository = workspace.open_registered("mi-organizacion", "api")
    result = runner.generate(repository, Path("results/sboms"))

print(result.model_dump_json(indent=2, exclude_none=True))
```

Se utiliza una instancia de `SyftRunner` por corrida secuencial, compartida entre
sus repositorios. Consulta la versión una sola vez mediante `syft version -o json`
y conserva tanto la versión como un eventual error de esa consulta. El timeout
se aplica a cada comando y puede configurarse en el constructor; `syft_binary`
permite indicar una ubicación alternativa del ejecutable.

La generación utiliza `syft scan dir:<clon> -o cyclonedx-json=<temporal>`, según
la [referencia de la CLI](https://oss.anchore.com/docs/reference/syft/cli/).
Comprueba el código de salida y la estructura básica del JSON: formato
CycloneDX, versión de especificación, versión del documento cuando existe y
lista de componentes con nombre y tipo. Esta comprobación no es una validación
completa contra el esquema CycloneDX. Una lista vacía o ausente representa cero
componentes; `metadata.component` no se incluye en el conteo.

Solo después de validar se mueve el archivo original, sin reserializarlo, a
`<output-directory>/<run-id>/<owner>/<repository>.cdx.json`. `run_id` es un
identificador único de la instancia. Las corridas nuevas conservan los archivos
anteriores; repetir un repositorio ya generado en la misma corrida produce un
error sin sobrescribirlo. La salida debe estar fuera del clon para no alterar
el contenido que Syft inventaría.

Los fallos se comunican como `SyftExecutionError`, con `stage`, `message` y
`syft_version` cuando se conoce. Las etapas son `syft_version`, `sbom_source`,
`sbom_generation`, `sbom_validation` y `sbom_write`. Los mensajes no incorporan
stdout ni stderr del proceso. Una generación fallida elimina su salida temporal
y permite procesar los demás repositorios con la misma instancia.

Las pruebas del ejecutor (`pytest tests/syft`) simulan procesos y archivos;
no requieren Syft instalado ni acceso a red. La comprobación con el binario
real y el contraste con archivos de dependencias corresponden a la feature
de verificación y documentación.

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
