const API_URL = window.PHISHGUARD_API_URL;

async function submitAuthForm(form, path, values, success) {
  const status = document.getElementById("formMessage");
  const button = form.querySelector('button[type="submit"]');
  status.textContent = "";
  status.classList.remove("error-message", "success-message");
  button.disabled = true;
  try {
    const response = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      credentials: "include",
      body: JSON.stringify(values)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request could not be completed.");
    status.textContent = data.message || success;
    status.classList.add("success-message");
    if (success) {
      setTimeout(() => { window.location.href = success; }, 350);
    }
  } catch (error) {
    status.textContent = error.message || "The server could not be reached. Start the Flask API and try again.";
    status.classList.add("error-message");
  } finally {
    button.disabled = false;
  }
}

document.getElementById("signupForm")?.addEventListener("submit", event => {
  event.preventDefault();
  const form = event.currentTarget;
  const password = document.getElementById("signupPassword").value;
  if (password !== document.getElementById("confirmPassword").value) {
    const status = document.getElementById("formMessage");
    status.textContent = "Passwords do not match.";
    status.className = "form-message error-message";
    return;
  }
  submitAuthForm(form, "/signup", {
    name: document.getElementById("name").value.trim(),
    email: document.getElementById("signupEmail").value.trim(),
    password
  }, "dashboard.html");
});

document.getElementById("loginForm")?.addEventListener("submit", event => {
  event.preventDefault();
  submitAuthForm(event.currentTarget, "/login", {
    email: document.getElementById("email").value.trim(),
    password: document.getElementById("password").value
  }, "dashboard.html");
});

document.getElementById("forgotForm")?.addEventListener("submit", event => {
  event.preventDefault();
  submitAuthForm(event.currentTarget, "/forgot-password", {
    email: document.getElementById("resetEmail").value.trim()
  }, "");
});

document.getElementById("resetForm")?.addEventListener("submit", event => {
  event.preventDefault();
  const password = document.getElementById("newPassword").value;
  if (password !== document.getElementById("confirmNewPassword").value) {
    const status = document.getElementById("formMessage");
    status.textContent = "Passwords do not match.";
    status.className = "form-message error-message";
    return;
  }
  submitAuthForm(event.currentTarget, "/reset-password", {
    token: new URLSearchParams(window.location.search).get("token") || "",
    password
  }, "index.html");
});
