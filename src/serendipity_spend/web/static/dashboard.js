(() => {
  const dataEl = document.getElementById("dashboard-data");
  if (!(dataEl instanceof HTMLScriptElement)) return;

  const raw = (dataEl.textContent || "").trim();
  if (!raw) return;

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return;
  }

  const rootStyles = getComputedStyle(document.documentElement);
  const bodyStyles = getComputedStyle(document.body);

  function getCanvas(id) {
    const el = document.getElementById(id);
    return el instanceof HTMLCanvasElement ? el : null;
  }

  function showEmpty(canvas, message) {
    const wrap = canvas.parentElement;
    if (!wrap) return;
    wrap.innerHTML = `<div class="chart-empty">${message}</div>`;
  }

  const Chart = window.Chart;
  if (!Chart) {
    const missing = "Charts unavailable (failed to load).";
    const c1 = getCanvas("claims-status-chart");
    const c2 = getCanvas("tasks-chart");
    const c3 = getCanvas("violations-chart");
    if (c1) showEmpty(c1, missing);
    if (c2) showEmpty(c2, missing);
    if (c3) showEmpty(c3, missing);
    return;
  }

  function cssVar(name, fallback) {
    const value = rootStyles.getPropertyValue(name).trim();
    return value || fallback;
  }

  const colors = {
    accent: cssVar("--accent", "#2563EB"),
    violet: cssVar("--violet", "#7C3AED"),
    warn: cssVar("--warn", "#D97706"),
    ok: cssVar("--ok", "#16A34A"),
    danger: cssVar("--danger", "#DC2626"),
    text: cssVar("--text-secondary", "#6B7280"),
    grid: cssVar("--border-subtle", "#F5F5F4"),
  };

  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ?? false;

  Chart.defaults.maintainAspectRatio = false;
  Chart.defaults.responsive = true;
  Chart.defaults.color = colors.text;
  Chart.defaults.font.family = bodyStyles.fontFamily;
  if (reducedMotion) Chart.defaults.animation = false;

  function statusColor(status) {
    switch (status) {
      case "DRAFT":
      case "NEEDS_EMPLOYEE_REVIEW":
      case "CHANGES_REQUESTED":
        return colors.warn;
      case "PROCESSING":
        return colors.accent;
      case "SUBMITTED":
      case "NEEDS_APPROVER_REVIEW":
        return colors.violet;
      case "APPROVED":
      case "READY_FOR_PAYMENT":
      case "PAID":
        return colors.ok;
      case "REJECTED":
        return colors.danger;
      default:
        return colors.accent;
    }
  }

  function severityColor(severity) {
    switch (severity) {
      case "FAIL":
        return colors.warn;
      case "NEEDS_INFO":
        return colors.warn;
      case "WARN":
        return colors.accent;
      case "PASS":
        return colors.ok;
      default:
        return colors.accent;
    }
  }

  const claimCanvas = getCanvas("claims-status-chart");
  if (claimCanvas) {
    const claimData = data.claim_status || {};
    const labels = Array.isArray(claimData.labels) ? claimData.labels : [];
    const counts = Array.isArray(claimData.counts) ? claimData.counts : [];
    const statuses = Array.isArray(claimData.statuses) ? claimData.statuses : [];

    const total = counts.reduce((acc, v) => acc + (Number(v) || 0), 0);
    if (!labels.length || !counts.length || total === 0) {
      showEmpty(claimCanvas, "No claims yet.");
    } else {
      const backgroundColor = statuses.map(statusColor);
      new Chart(claimCanvas, {
        type: "doughnut",
        data: {
          labels,
          datasets: [
            {
              data: counts,
              backgroundColor,
              borderWidth: 0,
              hoverOffset: 6,
            },
          ],
        },
        options: {
          cutout: "62%",
          plugins: {
            legend: {
              position: "bottom",
              labels: {
                boxWidth: 10,
                boxHeight: 10,
                usePointStyle: true,
                pointStyle: "circle",
              },
            },
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const value = Number(ctx.parsed) || 0;
                  const pct = total ? Math.round((value / total) * 100) : 0;
                  return `${ctx.label}: ${value} (${pct}%)`;
                },
              },
            },
          },
          onClick: (event, elements) => {
            if (!elements || elements.length === 0) return;
            const idx = elements[0].index;
            const status = statuses[idx];
            if (!status) return;
            const url = new URL(window.location.href);
            url.searchParams.set("status", status);
            url.searchParams.delete("stage");
            window.location.assign(url.toString());
          },
        },
      });
    }
  }

  const tasksCanvas = getCanvas("tasks-chart");
  if (tasksCanvas) {
    const taskData = data.task_categories || {};
    const labels = Array.isArray(taskData.labels) ? taskData.labels : [];
    const counts = Array.isArray(taskData.counts) ? taskData.counts : [];
    const total = counts.reduce((acc, v) => acc + (Number(v) || 0), 0);

    if (!labels.length || !counts.length || total === 0) {
      showEmpty(tasksCanvas, "No open tasks.");
    } else {
      const backgroundColor = labels.map((label) => {
        if (label === "Policy") return colors.accent;
        if (label === "Extraction") return colors.violet;
        return colors.warn;
      });
      new Chart(tasksCanvas, {
        type: "bar",
        data: {
          labels,
          datasets: [
            {
              label: "Open tasks",
              data: counts,
              backgroundColor,
              borderRadius: 10,
              borderSkipped: false,
            },
          ],
        },
        options: {
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: (ctx) => `${ctx.label}: ${ctx.parsed.y}`,
              },
            },
          },
          scales: {
            x: { grid: { display: false } },
            y: {
              beginAtZero: true,
              grid: { color: colors.grid },
              ticks: { precision: 0 },
            },
          },
        },
      });
    }
  }

  const violationsCanvas = getCanvas("violations-chart");
  if (violationsCanvas) {
    const violationData = data.violation_severity || {};
    const labels = Array.isArray(violationData.labels) ? violationData.labels : [];
    const counts = Array.isArray(violationData.counts) ? violationData.counts : [];
    const severities = Array.isArray(violationData.severities) ? violationData.severities : [];
    const total = counts.reduce((acc, v) => acc + (Number(v) || 0), 0);

    if (!labels.length || !counts.length || total === 0) {
      showEmpty(violationsCanvas, "No open policy violations.");
    } else {
      const backgroundColor = severities.map(severityColor);
      new Chart(violationsCanvas, {
        type: "bar",
        data: {
          labels,
          datasets: [
            {
              label: "Open violations",
              data: counts,
              backgroundColor,
              borderRadius: 10,
              borderSkipped: false,
            },
          ],
        },
        options: {
          indexAxis: "y",
          plugins: { legend: { display: false } },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: colors.grid },
              ticks: { precision: 0 },
            },
            y: { grid: { display: false } },
          },
        },
      });
    }
  }
})();
