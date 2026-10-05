import { signedIn as test, expect } from "./support/fixtures";

test("desktop navigation rail covers the full document including short viewports", async ({
  browser,
  screen,
}) => {
  await browser.setViewport({ width: 1280, height: 540 });
  await browser.goto("/");
  await expect(screen.getByRole("table")).toBeVisible();
  const geometry = await browser.evaluate(() => {
    const el = document.querySelector(".app-shell")!;
    return {
      rail: el.getBoundingClientRect().height,
      page: document.documentElement.scrollHeight,
      color: getComputedStyle(el).backgroundColor,
    };
  });
  expect(Math.abs(geometry.rail - geometry.page)).toBeLessThan(1);
  expect(geometry.color).toBe("rgb(23, 35, 34)");
  await expect(screen.getByRole("link", "Your environment")).toBeVisible();
});
test("assessment dialog traps forward and reverse keyboard focus and restores its trigger", async ({
  browser,
  screen,
}) => {
  await browser.goto("/");
  const trigger = screen.getByRole("button", "Assess observable");
  await trigger.click();
  await expect(screen.getByRole("dialog")).toBeVisible();
  for (const key of [
    "Tab",
    "Tab",
    "Tab",
    "Tab",
    "Shift+Tab",
    "Shift+Tab",
    "Shift+Tab",
    "Shift+Tab",
  ]) {
    await browser.keyboard.press(key);
    expect(
      await browser.evaluate(() => !!document.activeElement?.closest("dialog")),
    ).toBe(true);
  }
  await browser.keyboard.press("Escape");
  await expect(screen.getByRole("dialog")).not.toBeVisible();
  await expect(trigger).toBeFocused();
});
test("mobile navigation traps focus, closes on Escape and supports page navigation", async ({
  browser,
  screen,
}) => {
  await browser.setViewport({ width: 390, height: 600 });
  await browser.goto("/");
  const trigger = screen.getByRole("button", "Toggle navigation");
  await trigger.click();
  await expect(
    screen.getByRole("dialog", "Workspace navigation"),
  ).toBeVisible();
  for (let i = 0; i < 10; i++) {
    await browser.keyboard.press("Tab");
    expect(
      await browser.evaluate(
        () => !!document.activeElement?.closest(".sidebar"),
      ),
    ).toBe(true);
  }
  await browser.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  await trigger.click();
  await screen.getByRole("link", "Bulk analysis").click();
  await expect(
    screen.getByRole("heading", "From indicators to intelligence."),
  ).toBeVisible();
  await expect(
    screen.getByRole("dialog", "Workspace navigation"),
  ).not.toBeVisible();
});
for (const [path, heading] of [
  ["/", "Focus on what matters."],
  ["/bulk", "From indicators to intelligence."],
  ["/inventory", "Your environment"],
  ["/sources", "Intelligence sources"],
  ["/clusters", "Emerging clusters"],
] as const) {
  test(`mobile ${path} contains content within the viewport`, async ({
    browser,
    screen,
  }) => {
    await browser.setViewport({ width: 390, height: 844 });
    await browser.goto(path);
    await expect(screen.getByRole("heading", heading)).toBeVisible();
    expect(
      await browser.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
  });
}
