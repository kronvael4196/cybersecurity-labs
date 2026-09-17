"""Functional browser tests for the isolated CI deployment; no production identities."""
import json
import os
from pathlib import Path
import re

import pytest
from playwright.sync_api import expect

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "artifacts/screenshots"


@pytest.fixture(autouse=True)
def evidence_folder():
    EVIDENCE.mkdir(parents=True, exist_ok=True)


def test_pki_identity_sign_verify_and_revoke(page, tmp_path):
    env = dict(line.split("=", 1) for line in (ROOT / "05-pki-digital-signature/.env").read_text().splitlines() if "=" in line)
    page.goto("https://localhost:8443")
    expect(page.get_by_role("heading", name="Certificados y firma digital")).to_be_visible()
    page.locator("#token").fill(env["PKI_ADMIN_TOKEN"])
    page.get_by_role("button", name="Conectar", exact=True).click()
    expect(page.locator("#status")).to_contain_text("Conectado")
    page.locator('#issue input[name="name"]').fill("Identidad de prueba de interfaz")
    password = "Temporary-browser-test-2026"
    page.locator('#issue input[name="password"]').fill(password)
    with page.expect_download() as download:
        page.get_by_role("button", name="Emitir y descargar .p12").click()
    bundle = tmp_path / "identity.p12"
    download.value.save_as(bundle)
    assert bundle.stat().st_size > 0
    source = tmp_path / "documento.txt"
    source.write_text("Documento ficticio para verificar integridad.\n", encoding="utf-8")
    page.locator('#sign input[name="file"]').set_input_files(source)
    page.locator('#sign input[name="p12"]').set_input_files(bundle)
    page.locator('#sign input[name="password"]').fill(password)
    with page.expect_download() as download:
        page.get_by_role("button", name="Firmar y descargar", exact=True).click()
    signature = tmp_path / "signature.json"
    download.value.save_as(signature)
    page.locator('#verify input[name="file"]').set_input_files(source)
    page.locator('#verify input[name="signature"]').set_input_files(signature)
    page.get_by_role("button", name="Verificar firma", exact=True).click()
    expect(page.locator("#verification")).to_contain_text("Firma válida")
    page.screenshot(path=str(EVIDENCE / "pki-firma-valida.png"), full_page=True, mask=[page.locator("#token")], mask_color="#263e52")
    source.write_text("Contenido modificado", encoding="utf-8")
    page.locator('#verify input[name="file"]').set_input_files(source)
    page.get_by_role("button", name="Verificar firma", exact=True).click()
    expect(page.locator("#verification")).to_contain_text("Verificación fallida")
    source.write_text("Documento ficticio para verificar integridad.\n", encoding="utf-8")
    page.locator('#verify input[name="file"]').set_input_files(source)
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("row").filter(has_text="Identidad de prueba de interfaz").get_by_role("button", name="Revocar").click()
    expect(page.locator("#status")).to_contain_text("Certificado revocado")
    page.get_by_role("button", name="Verificar firma", exact=True).click()
    expect(page.locator("#verification")).to_contain_text("Certificado revocado")
    page.screenshot(path=str(EVIDENCE / "pki-revocacion.png"), full_page=True, mask=[page.locator("#token")], mask_color="#263e52")


def test_home_lab_and_scanner_report(page):
    page.goto("http://localhost:3001")
    expect(page.get_by_role("heading", name="Welcome to OWASP Juice Shop!")).to_be_visible(timeout=60000)
    page.get_by_role("button", name="dismiss cookie message").click()
    page.get_by_role("button", name="Close Welcome Banner").click()
    expect(page.get_by_text("All Products", exact=True)).to_be_visible()
    page.screenshot(path=str(EVIDENCE / "juice-shop.png"), full_page=True)
    page.goto("http://localhost:3003")
    expect(page.get_by_role("heading", name="Prácticas web: hardened")).to_be_visible()
    page.screenshot(path=str(EVIDENCE / "home-lab-corregido.png"), full_page=True)
    report = ROOT / "artifacts/scanner/home-lab.json"
    results = json.loads(report.read_text())["results"]
    assert len(results) == 3 and all(item["state"] == "open" and item["service"] == "http" for item in results)
    page.goto((ROOT / "artifacts/scanner/home-lab.html").as_uri())
    expect(page.get_by_role("heading", name="Reconocimiento TCP")).to_be_visible()
    page.screenshot(path=str(EVIDENCE / "scanner-home-lab.png"), full_page=True)


def test_kibana_live_dashboard(page):
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto("http://localhost:5601/app/dashboards#/view/mini-siem-overview")
    expect(page.get_by_text("Mini SIEM — actividad SSH", exact=False).first).to_be_visible(timeout=120000)
    expect(page.get_by_text("Autenticaciones fallidas", exact=False).first).to_be_visible(timeout=60000)
    # Wait for actual metric rendering, not merely the dashboard shell.
    try:
        expect(page.locator('[data-test-subj="metric_value"]').first).to_be_visible(timeout=60000)
    finally:
        page.screenshot(path=str(EVIDENCE / "kibana-diagnostic.png"), full_page=True)
        (EVIDENCE / "kibana-diagnostic.html").write_text(page.content(), encoding="utf-8")
        (EVIDENCE / "kibana-errors.json").write_text(json.dumps(errors), encoding="utf-8")
    assert page.locator('[data-test-subj="metric_value"]').count() >= 3
    values = page.locator('[data-test-subj="metric_value"]').all_text_contents()
    assert all(re.search(r"[1-9]", value) for value in values), values
    page.screenshot(path=str(EVIDENCE / "kibana-ssh-alertas.png"), full_page=True)


def test_pytest_report_evidence(page):
    page.goto((ROOT / "artifacts/pytest/05-pki-digital-signature.html").as_uri())
    expect(page.get_by_text(re.compile(r"\d+ Passed"))).to_be_visible()
    page.screenshot(path=str(EVIDENCE / "pytest-pki.png"), full_page=True)
