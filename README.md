# Repo Vulnerability Miner

CLI en Python que clona repositorios de GitHub, analiza hallazgos con CodeQL y
genera un SBOM CycloneDX JSON con Syft para cada repositorio.

## Requisitos

- Python 3.11 o superior, Git y CodeQL CLI.
- [Syft 1.48.0](https://github.com/anchore/syft/releases/tag/v1.48.0).
- `GITHUB_TOKEN` solo para `miner scan`.

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

La CI usa Syft **1.48.0**. En Linux x86_64:

```bash
SYFT_VERSION=1.48.0
curl --fail --location --output /tmp/syft.tar.gz \
  "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
tar -xzf /tmp/syft.tar.gz -C /tmp syft
mkdir -p "$HOME/.local/bin"
install -m 0755 /tmp/syft "$HOME/.local/bin/syft"
export PATH="$HOME/.local/bin:$PATH"
syft version -o json
```

En macOS, descarga el archivo `darwin_amd64` o `darwin_arm64` del
[release oficial](https://github.com/anchore/syft/releases/tag/v1.48.0) y deja
el binario en `PATH`.

## Uso rápido

Configura un token de GitHub y ejecuta un escaneo. Este comando clona los
repositorios, ejecuta CodeQL y genera un SBOM para cada clon:

```bash
export GITHUB_TOKEN="tu-token"
miner scan \
  --organization mi-organizacion \
  --repos-dir results/repos \
  --sbom-dir results/sboms \
  --output results/scan.json
```

Para limitar la ejecución, repite `--repository`:

```bash
miner scan --organization mi-organizacion --repository api --repository web \
  --repos-dir results/repos --output results/scan.json
```

`scan` conserva los clones en `.miner/repos` por defecto, o en el directorio
indicado por `--repos-dir`. Las siguientes ejecuciones reutilizan esos clones y
su `manifest.json`; no hacen `fetch` ni `pull`.

## Regenerar SBOMs sin CodeQL

Después de un escaneo, reutiliza los clones locales sin token, GitHub ni CodeQL:

```bash
unset GITHUB_TOKEN
miner sbom \
  --organization mi-organizacion \
  --repos-dir results/repos \
  --output-dir results/regenerated-sboms \
  --output results/sbom-report.json
```

También admite `--repository api --repository web`. El directorio de clones
debe ser el mismo usado en el escaneo.

## Archivos generados

| Ruta | Contenido |
| --- | --- |
| `results/scan.json` | Informe consolidado de CodeQL y del SBOM generado durante `scan`. |
| `results/sboms/<run-id>/<owner>/<repo>.cdx.json` | SBOM CycloneDX JSON original de cada repositorio. |
| `results/repos/manifest.json` | Índice de los clones persistentes. Mantenerlo junto a `results/repos/`. |
| `results/sbom-report.json` | Informe de la ejecución independiente `sbom`. |
| `results/regenerated-sboms/<run-id>/<owner>/<repo>.cdx.json` | SBOMs regenerados sin CodeQL. |

Puedes revisar un informe con:

```bash
python -m json.tool results/scan.json
python -m json.tool results/sbom-report.json
```

Cada repositorio incluye su nombre completo, commit, resultado de CodeQL y
metadatos `sbom`: `status`, fecha de generación, versión de Syft, cantidad de
componentes y ruta del artefacto. Los estados `generated`, `failed` y `skipped`
distinguen un SBOM exitoso sin componentes (`component_count: 0`) de un error.
El error de un repositorio queda en el informe y no detiene los demás.

## Verificación

Ejecuta las pruebas unitarias:

```bash
pytest -q
```

La comprobación real usa los archivos versionados de
`tests/fixtures/sbom/` y contrasta `express@4.21.0` de `package-lock.json` y
`requests@2.32.3` de `requirements.txt`:

```bash
SYFT_BINARY="$(command -v syft)" EXPECTED_SYFT_VERSION=1.48.0 \
  pytest tests/syft/test_real_integration.py
```

Syft también puede incluir el proyecto raíz y los archivos de declaración o
bloqueo como componentes. Por eso el total puede ser mayor que las dependencias
contrastadas. El inventario depende de los archivos presentes y de lo que Syft
pueda detectar; no garantiza dependencias dinámicas o ausentes del clon.

## Lenguajes soportados

CodeQL analiza JavaScript y TypeScript mediante la suite
`javascript-security-extended`. Syft se ejecuta sobre todos los repositorios
clonados, incluso cuando no son compatibles con CodeQL.
