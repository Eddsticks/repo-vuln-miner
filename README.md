# Repo Vulnerability Miner

CLI en Python para recuperar repositorios de GitHub y analizar hallazgos de
seguridad mediante CodeQL. El análisis de organizaciones se incorporará en las
siguientes funcionalidades del proyecto.

## Requisitos

- Python 3.11 o superior.
- Git y CodeQL CLI instalados para ejecutar los futuros análisis.

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

Ejecutar un escaneo y guardar el informe JSON:

```bash
miner scan --organization mi-organizacion --output report.json
```

Para limitar la corrida a repositorios concretos, repetir `--repository`:

```bash
miner scan --organization mi-organizacion --output report.json --repository api --repository web
```

El progreso se muestra por stderr; el informe JSON se escribe solo en el archivo
indicado por `--output`.

## Autenticación con GitHub

El miner usará `GITHUB_TOKEN` de forma opcional para aumentar los límites de la
API y acceder a repositorios privados autorizados. Para organizaciones públicas
puede ejecutarse sin token.

```bash
export GITHUB_TOKEN="tu-token"
```

No guardes el token en archivos versionados ni lo incluyas en la URL de un
repositorio.

## Lenguajes soportados

La primera versión habilita análisis CodeQL para JavaScript y TypeScript con la
suite `javascript-security-extended`. El registro de adaptadores permite añadir
otros lenguajes sin modificar el catálogo de GitHub ni la lógica de clonación.
