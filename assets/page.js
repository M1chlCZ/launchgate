(() => {
  const status = document.getElementById("status");
  const form = document.getElementById("code-form");
  const input = document.getElementById("code-input");
  let token = location.hash.slice(1);
  let submitted = false;
  if (!token) {
    document.getElementById("invite").addEventListener("click", () => {
      status.textContent = "Open the private invitation link that you received.";
    });
    return;
  }
  history.replaceState(null, "", location.pathname + location.search);
  const exchange = (code) => {
    status.textContent = "Opening your invitation...";
    return fetch("/_launch/access", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(code ? { token, code } : { token }),
      credentials: "same-origin",
      cache: "no-store",
    });
  };
  const settle = (response) => {
    if (response.ok) {
      token = "";
      location.replace("/");
      return;
    }
    if (response.status === 401) {
      form.hidden = false;
      input.focus();
      input.select();
      status.textContent = submitted
        ? "The verification code was not accepted. Try again."
        : "Enter the verification code from your authenticator app.";
      return;
    }
    token = "";
    status.textContent =
      response.status === 429
        ? "Too many attempts. Wait a few minutes and try again."
        : "This invitation has expired or is unavailable. Ask for a new link.";
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    submitted = true;
    exchange(input.value.trim())
      .then(settle)
      .catch(() => {
        status.textContent = "The connection failed. Try again.";
      });
  });
  exchange("")
    .then(settle)
    .catch(() => {
      token = "";
      status.textContent =
        "This invitation has expired or is unavailable. Ask for a new link.";
    });
})();
