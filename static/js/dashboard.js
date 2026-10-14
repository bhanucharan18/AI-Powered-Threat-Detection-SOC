(function () {
  var el = document.getElementById("dash-data");
  if (!el) return;
  if (typeof Chart === "undefined") {
    document.getElementById("chart-fallback").hidden = false;
    return;
  }
  var d = JSON.parse(el.textContent);
  var css = getComputedStyle(document.documentElement);
  var c = function (n) { return css.getPropertyValue(n).trim(); };
  Chart.defaults.color = c("--muted");
  Chart.defaults.borderColor = c("--line");

  new Chart(document.getElementById("activity"), {
    type: "bar",
    data: {
      labels: d.activity.map(function (a) { return a.hour.slice(5).replace(" ", " "); }),
      datasets: [
        { label: "Successful", data: d.activity.map(function (a) { return a.success; }), backgroundColor: c("--ok"), stack: "s" },
        { label: "Failed", data: d.activity.map(function (a) { return a.failure; }), backgroundColor: c("--bad"), stack: "s" }
      ]
    },
    options: { responsive: true, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } }
  });

  var sev = ["low", "medium", "high", "critical"];
  new Chart(document.getElementById("severity"), {
    type: "bar",
    data: {
      labels: sev,
      datasets: [{ label: "Alerts", data: sev.map(function (s) { return d.severity[s]; }),
        backgroundColor: [c("--low"), c("--med"), c("--high"), c("--crit")] }]
    },
    options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
  });
})();
