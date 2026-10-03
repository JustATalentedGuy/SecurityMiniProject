import { test, expect } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";
import { readFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const screenshotDir = fileURLToPath(
  new URL("../../docs/screenshots/", import.meta.url),
);
const password = randomBytes(18).toString("base64url");
const sample = Buffer.from(
  "Confidential: Alice → Bob\nBinary bytes: \0\xff\n",
  "utf8",
);
let aliceContext, bobContext, alice, bob;
const browserErrors = [];

test.describe.configure({ mode: "serial" });
test.beforeAll(async ({ browser }) => {
  await mkdir(screenshotDir, { recursive: true });
  aliceContext = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  bobContext = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  alice = await aliceContext.newPage();
  bob = await bobContext.newPage();
  alice.on("pageerror", (error) => browserErrors.push(error.message));
  bob.on("pageerror", (error) => browserErrors.push(error.message));
  await alice.goto("/");
  await alice.screenshot({
    path: path.join(screenshotDir, "login.png"),
    fullPage: true,
  });
  for (const [page, username] of [
    [alice, "alice"],
    [bob, "bob"],
  ]) {
    await page.goto("/");
    await page.getByRole("button", { name: "Register", exact: true }).click();
    await page.getByLabel("Username", { exact: true }).fill(username);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page
      .getByRole("button", { name: "Generate keys & register" })
      .click();
    await expect(
      page.getByRole("heading", { name: `Welcome back, ${username}.` }),
    ).toBeVisible({ timeout: 30000 });
  }
});
test.afterAll(async () => {
  await aliceContext?.close();
  await bobContext?.close();
});

async function refresh(page) {
  await page
    .getByRole("button", { name: "Refresh workspace", exact: true })
    .click();
}
async function exchange(filename) {
  await alice.getByRole("link", { name: "Send file", exact: true }).click();
  await alice.getByLabel("Recipient", { exact: true }).selectOption({
    label: await alice
      .getByLabel("Recipient")
      .locator("option")
      .filter({ hasText: "bob ·" })
      .textContent(),
  });
  await alice
    .getByLabel("File to send")
    .setInputFiles({ name: filename, mimeType: "text/plain", buffer: sample });
  await alice
    .getByRole("button", { name: "Start authenticated exchange" })
    .click();
  await expect(
    alice.getByRole("link", { name: "Continue transfer →" }),
  ).toBeVisible();
  const url = await alice
    .getByRole("link", { name: "Continue transfer →" })
    .getAttribute("href");
  await alice.getByRole("link", { name: "Continue transfer →" }).click();
  await bob.getByRole("link", { name: "Received files", exact: true }).click();
  await refresh(bob);
  await expect(bob.getByRole("link", { name: filename })).toBeVisible();
  await bob.getByRole("link", { name: filename }).click();
  await expect(
    bob.getByRole("button", { name: "Accept key exchange" }),
  ).toBeVisible();
  await bob.getByRole("button", { name: "Accept key exchange" }).click();
  await expect(bob.getByText("Signed response sent.")).toBeVisible();
  await refresh(alice);
  await expect(
    alice.getByRole("button", { name: "Encrypt & upload" }),
  ).toBeVisible();
  await alice.getByRole("button", { name: "Encrypt & upload" }).click();
  await expect(alice.getByText("Ciphertext uploaded.")).toBeVisible();
  await refresh(bob);
  await expect(
    bob.getByRole("button", { name: "Verify & download", exact: true }),
  ).toBeVisible();
  return url.split("/").at(-1);
}

test("Alice → Bob: authenticated exchange and exact downloaded plaintext", async () => {
  await exchange("confidential.txt");
  const downloaded = bob.waitForEvent("download");
  await bob
    .getByRole("button", { name: "Verify & download", exact: true })
    .click();
  const result = await downloaded;
  expect(result.suggestedFilename()).toBe("confidential.txt");
  expect(await readFile(await result.path())).toEqual(sample);
  await expect(
    bob.getByText("All checks passed. The decrypted file"),
  ).toBeVisible();
  await expect(
    bob.getByRole("button", { name: "Verify & download again" }),
  ).toBeVisible();
  await bob.screenshot({
    path: path.join(screenshotDir, "transfer.png"),
    fullPage: true,
  });
  await alice.getByRole("link", { name: "Dashboard", exact: true }).click();
  await refresh(alice);
  await expect(
    alice.getByRole("link", { name: "confidential.txt" }),
  ).toBeVisible();
  await alice.screenshot({
    path: path.join(screenshotDir, "dashboard.png"),
    fullPage: true,
  });
});

test("controlled ciphertext, signature and replay attacks are rejected and monitored", async () => {
  for (const [attack, expected] of [
    ["tamper", "Encrypted file fingerprint mismatch"],
    ["signature", "signature is invalid"],
  ]) {
    const id = await exchange(`${attack}-sample.txt`);
    const response = await alice.evaluate(
      async ({ id, attack }) => {
        const result = await fetch(`/api/v1/demo/transfers/${id}/${attack}`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${sessionStorage.getItem("ssx:token")}`,
          },
        });
        return result.status;
      },
      { id, attack },
    );
    expect(response).toBe(200);
    await refresh(bob);
    await bob
      .getByRole("button", { name: "Verify & download", exact: true })
      .click();
    await expect(bob.getByRole("alert")).toContainText(expected);
  }
  await alice.getByRole("link", { name: /Attack lab/ }).click();
  await alice
    .getByLabel("Disposable transfer for file attacks")
    .selectOption({ index: 1 });
  await alice
    .getByRole("button", { name: "Replay Request", exact: true })
    .click();
  await expect(
    alice.getByText("DEFENSE RESPONDED", { exact: true }),
  ).toBeVisible();
  await expect(
    alice
      .getByText("This nonce has already been consumed", { exact: false })
      .first(),
  ).toBeVisible();
  await alice.getByRole("link", { name: "Security monitor" }).click();
  await expect(
    alice.getByText("FILE TAMPERING DETECTED", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    alice.getByText("SIGNATURE INVALID", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    alice.getByText("REPLAY ATTACK", { exact: true }).first(),
  ).toBeVisible();
  await alice.screenshot({
    path: path.join(screenshotDir, "security.png"),
    fullPage: true,
  });
});

test("a correctly signed corrupted GCM tag is rejected by recipient decryption", async () => {
  const pattern = "**/api/v1/transfers/*/upload";
  await alice.route(pattern, async (route) => {
    const headers = { ...route.request().headers() };
    const ciphertext = Buffer.from(route.request().postDataBuffer());
    ciphertext[ciphertext.length - 1] ^= 1;
    const metadata = JSON.parse(
      Buffer.from(headers["x-transfer-metadata"], "base64").toString("utf8"),
    );
    metadata.ciphertext_sha256 = createHash("sha256")
      .update(ciphertext)
      .digest("hex");
    headers["x-transfer-signature"] = await alice.evaluate(
      async ({ metadata, password }) => {
        const { sign } = await import("/src/utils/crypto.js");
        const { loadEnvelope, openVault } =
          await import("/src/services/vault.js");
        const vault = await openVault(loadEnvelope("alice"), password);
        return sign(vault.identityPrivate, metadata);
      },
      { metadata, password },
    );
    headers["x-transfer-metadata"] = Buffer.from(
      JSON.stringify(metadata),
    ).toString("base64");
    await route.continue({ headers, postData: ciphertext });
  });
  await exchange("invalid-gcm-tag.txt");
  await alice.unroute(pattern);
  await bob
    .getByRole("button", { name: "Verify & download", exact: true })
    .click();
  await expect(bob.getByRole("alert")).toContainText(
    "AES authentication or fingerprint verification failed",
  );
  await expect(
    bob.getByText("TAMPERED", { exact: true }).first(),
  ).toBeVisible();
});

test("live MITM comparison and login throttling show genuine mechanism outcomes", async () => {
  await alice.getByRole("link", { name: /Attack lab/ }).click();
  await alice
    .getByRole("button", { name: "Simulate MITM on Plain DH", exact: true })
    .click();
  await expect(
    alice.getByText("ATTACK SUCCEEDED", { exact: true }),
  ).toBeVisible();
  await alice
    .getByRole("button", {
      name: "Simulate MITM on Authenticated DH",
      exact: true,
    })
    .click();
  await expect(
    alice.getByText("DEFENSE RESPONDED", { exact: true }),
  ).toBeVisible();
  await alice.screenshot({
    path: path.join(screenshotDir, "attack-lab.png"),
    fullPage: true,
  });
  await alice
    .getByRole("button", { name: "Run Failed Login Simulation", exact: true })
    .click();
  await expect(alice.locator("pre")).toContainText("429");
  await alice
    .getByRole("button", { name: "Reset my demo login cooldown" })
    .click();
  await expect(alice.locator("pre")).toContainText("reset");
});

test("encrypted vault backup unlocks RSA challenge login and survives reload", async () => {
  await alice.getByRole("link", { name: "Identity & keys" }).click();
  const backupPromise = alice.waitForEvent("download");
  await alice
    .getByRole("button", { name: "Download encrypted key vault" })
    .click();
  const backup = await backupPromise;
  const contents = JSON.parse(await readFile(await backup.path(), "utf8"));
  expect(contents.version).toBe(1);
  expect(contents.identityPrivate).toBeUndefined();
  await alice.getByRole("button", { name: "Lock & sign out" }).click();
  await alice.evaluate(() => localStorage.clear());
  await alice.getByLabel("Import encrypted key vault").setInputFiles({
    name: "alice.vault.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(contents)),
  });
  await alice.getByLabel("Username", { exact: true }).fill("alice");
  await alice.getByLabel("Password", { exact: true }).fill(password);
  await alice.getByLabel("Use RSA challenge-response authentication").check();
  await alice.getByRole("button", { name: "Sign challenge & enter" }).click();
  await expect(
    alice.getByRole("heading", { name: "alice's identity" }),
  ).toBeVisible();
  await alice.reload();
  await expect(
    alice.getByRole("heading", { name: "Welcome back", exact: true }),
  ).toBeVisible();
  await alice.getByLabel("Username", { exact: true }).fill("alice");
  await alice.getByLabel("Password", { exact: true }).fill(password);
  await alice.getByRole("button", { name: "Sign in securely" }).click();
  await expect(
    alice.getByRole("heading", { name: "alice's identity" }),
  ).toBeVisible();
});

test("responsive workspace fits a mobile viewport and surfaces no browser errors", async () => {
  const errors = [];
  alice.on("pageerror", (error) => errors.push(error.message));
  await alice.setViewportSize({ width: 390, height: 844 });
  await alice.getByRole("link", { name: "Dashboard", exact: true }).click();
  await expect(
    alice.getByRole("heading", { name: "Welcome back, alice." }),
  ).toBeVisible();
  const dimensions = await alice.evaluate(() => ({
    width: document.documentElement.scrollWidth,
    viewport: innerWidth,
  }));
  expect(dimensions.width).toBeLessThanOrEqual(dimensions.viewport);
  expect(errors).toEqual([]);
  expect(browserErrors).toEqual([]);
  await alice.screenshot({
    path: path.join(screenshotDir, "mobile.png"),
    fullPage: true,
  });
});
