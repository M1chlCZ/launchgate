(() => {
  const status = document.getElementById("status");
  let token = location.hash.slice(1);
  if (!token) {
    document.getElementById("invite").addEventListener("click", () => {
      status.textContent = "Open the private invitation link that you received.";
    });
    return;
  }
  history.replaceState(null, "", location.pathname + location.search);
  status.textContent = "Opening your invitation...";
  fetch("/_launch/access", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
    credentials: "same-origin",
    cache: "no-store",
  })
    .then((response) => {
      token = "";
      if (!response.ok) {
        throw new Error();
      }
      location.replace("/");
    })
    .catch(() => {
      token = "";
      status.textContent =
        "This invitation has expired or is unavailable. Ask for a new link.";
    });
})();
