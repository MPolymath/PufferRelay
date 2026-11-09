# Release checklist

1. Bump the version in **both** `pyproject.toml` and `PufferRelay/__init__.py`.
2. Add a `CHANGELOG.md` section.
3. Regenerate the wiki and the packaged catalog:
   `python scripts/build_wiki.py`.
4. Run the suite and the wiki check:
   `python -m pytest PufferRelay/tests -q && python scripts/build_wiki.py --check`.
5. Build and inspect:
   `rm -rf dist build *.egg-info && python -m build && python -m twine check dist/*`.
   Confirm the wheel contains `PufferRelay/database`, `protocols`, `utils`,
   `pcap_processing` and `catalog_data.yaml`.
6. Upload (credentials in `~/.pypirc`): `python -m twine upload dist/*`.
7. Verify from PyPI in a **fresh** venv with `--no-cache-dir`:
   `pip install pufferrelay==<version>` and run `pufferrelay --version`,
   `pufferrelay --detections`, and an import of a subpackage.
8. Commit, push, wait for the CI matrix, then tag and release:
   `git tag -a v<version> -m "..." && git push origin v<version>` and
   `gh release create v<version> --title ... --notes-file CHANGELOG.md`.
9. Sync the wiki to GitBook:
   - the space content is updated with a change request (insert/update pages,
     then merge);
   - **public site publishing requires a paid GitBook plan** — without it the
     space stays private (preview URL only).
10. Docker: `docker build -t pufferrelay:<version> .` and a `--version` smoke
    run. A registry push is optional and needs a registry the operator owns.
