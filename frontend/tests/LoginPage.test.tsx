import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { login, register, push } = vi.hoisted(() => ({
  login: vi.fn(),
  register: vi.fn(),
  push: vi.fn(),
}));

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ login, register }) }));

import LoginPage from "@/app/login/page";
import { ApiError } from "@/lib/api";

describe("LoginPage", () => {
  beforeEach(() => {
    login.mockReset();
    register.mockReset();
    push.mockReset();
  });

  it("takes a standard user to the home page after sign-in", async () => {
    login.mockResolvedValue({ roles: ["USER"] });
    render(<LoginPage />);

    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct-horse" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(push).toHaveBeenCalledWith("/"));
  });

  it("takes analysts to the security panel after sign-in", async () => {
    login.mockResolvedValue({ roles: ["SECURITY_ANALYST"] });
    render(<LoginPage />);

    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "analyst@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct-horse" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(push).toHaveBeenCalledWith("/security-panel"));
  });

  it("explains invalid credentials and how to register", async () => {
    login.mockRejectedValue(new ApiError(401, "Invalid email or password"));
    render(<LoginPage />);

    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/If you are new, choose/);
    expect(push).not.toHaveBeenCalled();
  });
});
