/**
 * PhishRadar - AI-Based Phishing Detection & Decision Support System
 * Shell Coordinator: Manages workspaces, navigation, category pills,
 * keyboard shortcuts, health telemetry, and interactive toasts.
 */

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupCategoryPills();
  setupQuickActions();
  setupKeyboardShortcuts();
  setupSidebarCollapse();
  setupHealthMonitoring();
  setupGlobalSearch();
  setupSystemWidgets();

  // Initialize sub-modules
  if (typeof setupBatchCSVScanner === "function") setupBatchCSVScanner();
  if (typeof setupLiveScanner === "function") setupLiveScanner();
});

// 1. Navigation & Workspace Switching
const WORKSPACE_TITLES = {
  "workspace-analyzer": "Single Email Scan",
  "workspace-fleet": "Bulk CSV Scan"
};

function switchWorkspace(targetWorkspaceId) {
  if (!targetWorkspaceId) return;

  const navItems = document.querySelectorAll(".nav-item[data-workspace]");
  const catPills = document.querySelectorAll(".cat-pill[data-workspace]");
  const workspaces = document.querySelectorAll(".workspace");

  // Sync sidebar active state
  navItems.forEach(n => {
    if (n.dataset.workspace === targetWorkspaceId) {
      n.classList.add("active");
    } else {
      n.classList.remove("active");
    }
  });

  // Sync category pills active state
  catPills.forEach(p => {
    if (p.dataset.workspace === targetWorkspaceId) {
      p.classList.add("active");
    } else {
      p.classList.remove("active");
    }
  });

  // Switch workspace visibility
  workspaces.forEach(ws => {
    if (ws.id === targetWorkspaceId) {
      ws.classList.add("active");
      ws.scrollIntoView({ behavior: "smooth", block: "start" });
    } else {
      ws.classList.remove("active");
    }
  });

  // Close mobile sidebar if open
  const sidebar = document.getElementById("app-sidebar");
  if (sidebar && sidebar.classList.contains("open")) {
    sidebar.classList.remove("open");
  }
}

function setupNavigation() {
  const navItems = document.querySelectorAll(".nav-item[data-workspace]");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      switchWorkspace(item.dataset.workspace);
    });
  });
}

// 2. Category Filter Pills Row (Top bar under header)
function setupCategoryPills() {
  const catPills = document.querySelectorAll(".cat-pill[data-workspace]");
  catPills.forEach(pill => {
    pill.addEventListener("click", () => {
      switchWorkspace(pill.dataset.workspace);
    });
  });
}

// 3. Header Strip Quick Actions
function setupQuickActions() {
  const quickScannerBtn = document.getElementById("btn-quick-scanner");
  if (quickScannerBtn) {
    quickScannerBtn.addEventListener("click", () => {
      switchWorkspace("workspace-analyzer");
      const textarea = document.getElementById("email-content");
      if (textarea) textarea.focus();
    });
  }

  const quickBatchBtn = document.getElementById("btn-quick-batch");
  if (quickBatchBtn) {
    quickBatchBtn.addEventListener("click", () => {
      switchWorkspace("workspace-fleet");
    });
  }
}

// 4. Sidebar Collapse & Mobile Drawer
function setupSidebarCollapse() {
  const collapseBtn = document.getElementById("btn-collapse-sidebar");
  const toggleBtn = document.getElementById("btn-toggle-sidebar");
  const sidebar = document.getElementById("app-sidebar");

  if (collapseBtn && sidebar) {
    collapseBtn.addEventListener("click", () => {
      sidebar.classList.toggle("collapsed");
    });
  }

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      sidebar.classList.toggle("open");
    });

    document.addEventListener("click", (e) => {
      if (sidebar.classList.contains("open") && !sidebar.contains(e.target) && e.target !== toggleBtn) {
        sidebar.classList.remove("open");
      }
    });
  }
}

// 5. Keyboard Shortcuts (1-2 to switch workspaces, Esc for modals)
function setupKeyboardShortcuts() {
  const workspaceIds = [
    "workspace-analyzer",
    "workspace-fleet"
  ];

  document.addEventListener("keydown", (e) => {
    const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : "";
    if (activeTag === "input" || activeTag === "textarea" || activeTag === "select") {
      return;
    }

    const key = e.key;
    if (["1", "2"].includes(key)) {
      const index = parseInt(key, 10) - 1;
      const targetId = workspaceIds[index];
      if (targetId) {
        switchWorkspace(targetId);
        showToast(`Opened: ${WORKSPACE_TITLES[targetId]}`);
      }
    }
  });
}

// 6. Global Search Pill in Top Header
function setupGlobalSearch() {
  const searchInput = document.getElementById("global-search-input");
  if (!searchInput) return;

  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const q = searchInput.value.trim().toLowerCase();
      if (!q) return;

      if (q.includes("batch") || q.includes("csv") || q.includes("fleet")) {
        switchWorkspace("workspace-fleet");
      } else {
        switchWorkspace("workspace-analyzer");
        showToast(`Searching for "${q}"...`);
      }
    }
  });
}

// 7. Server Health Monitoring
async function setupHealthMonitoring() {
  checkHealth();
  setInterval(checkHealth, 30000);
}

async function checkHealth() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    console.log("System Health:", data);
  } catch (err) {
    console.warn("Backend server check:", err);
  }
}

// 8. Help & Notification Widgets
function setupSystemWidgets() {
  const chatBubble = document.getElementById("btn-floating-chat");
  const headerChat = document.getElementById("btn-header-chat");

  const openStatus = () => {
    showToast("System Ready: All email protection checks are active.");
  };

  if (chatBubble) chatBubble.addEventListener("click", openStatus);
  if (headerChat) headerChat.addEventListener("click", openStatus);

  const notifBtn = document.getElementById("btn-header-notif");
  if (notifBtn) {
    notifBtn.addEventListener("click", () => {
      showToast("All security checks are running normally.");
    });
  }
}

// 9. Global Toast Notification
function showToast(msg) {
  const box = document.getElementById("toast-box");
  if (!box) return;

  const t = document.createElement("div");
  t.className = "toast-msg";
  t.innerHTML = `
    <svg class="ui-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    <span>${escapeHtmlApp(msg)}</span>
  `;
  box.appendChild(t);

  setTimeout(() => {
    t.style.opacity = "0";
    t.style.transform = "translateY(10px)";
    t.style.transition = "all 0.3s ease";
    setTimeout(() => t.remove(), 300);
  }, 3500);
}

function escapeHtmlApp(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
