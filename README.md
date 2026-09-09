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

El futuro comando `miner scan` recibirá una organización de GitHub y un archivo
de salida JSON.

## Autenticación con GitHub

El miner usará `GITHUB_TOKEN` de forma opcional para aumentar los límites de la
API y acceder a repositorios privados autorizados. Para organizaciones públicas
puede ejecutarse sin token.

```bash
export GITHUB_TOKEN="tu-token"
```

No guardes el token en archivos versionados ni lo incluyas en la URL de un
repositorio.
