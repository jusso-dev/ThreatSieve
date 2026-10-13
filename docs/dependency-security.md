# Dependency checks

CI resolves and installs the OpenCTI connector requirements, runs `pip check`, audits Python dependencies, and separately audits production JavaScript dependencies. Import/transport behavior remains covered by offline connector tests. Passing mocked tests alone does not prove that dependency constraints are installable.

## OpenCTI compatibility, 13 October 2026

The current pinned `pycti==7.261008.0` distribution requires `requests>=2.32.0,<2.34.0`. Raising the direct requirement to 2.34.2 made a fresh installation impossible. ThreatSieve therefore requires `requests>=2.33.1,<2.34.0`, the current compatible line. Requests 2.33 includes the CVE-2026-25645 security fix; the 2.34 release adds typing and behavioral changes. See the [Requests release history](https://requests.readthedocs.io/en/latest/community/updates/) and [pycti distribution](https://pypi.org/project/pycti/7.261008.0/).

## JavaScript build dependency patch

The OpenNext build tool indirectly depends on glob 10. The workspace overrides only vulnerable glob versions `>=10.2.0 <10.5.0` to the patched 10.5.0 release. This fixes the CLI command-injection advisory without suppressing the production audit or moving consumers to another major version. Remove the override when upstream dependency constraints require a patched release. [Upstream advisory](https://github.com/advisories/GHSA-5j98-mcp5-4vw2).

## Narrow build-time exception

`PYSEC-2026-3447` / `CVE-2026-59890` / `GHSA-h35f-9h28-mq5c` affects Unicode exclusion matching when setuptools builds source distributions on normalization-preserving filesystems. pycti pins setuptools to the 82.0 series; the fix is in 83.0.0. Overriding pycti's dependency contract would produce an unsupported installation.

CI explicitly excludes this single advisory from its failure gate. ThreatSieve does not build or publish Python source distributions and the deployed connector runs on Linux, so the affected packaging workflow is absent. This is an applicability exception, not a claim that the upstream package has been patched. All other Python advisories fail the gate. Remove the exception when a compatible pycti release admits setuptools 83 or later, or before introducing a Python source-distribution publication workflow. [Upstream advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c).
