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
