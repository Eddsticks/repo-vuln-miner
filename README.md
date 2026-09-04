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
