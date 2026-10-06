import { signedIn as test, expect, request } from "./support/fixtures";
test("isolated workspace opens and API agrees with the UI", async ({
  browser,
  screen,
  workspace,
}) => {
  await browser.goto("/");
  await expect(screen.getByRole("heading", "Threat operations")).toBeVisible();
  const response = await request(workspace, "/v1/assessments");
  expect(response.status).toBe(200);
  await screen.getByRole("button", "All intelligence").click();
  await expect(
    screen.getByRole("link", "Investigate beacon.demo.example"),
  ).toBeVisible();
});
