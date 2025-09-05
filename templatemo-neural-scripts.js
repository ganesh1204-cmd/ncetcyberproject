// Global state
let analysisHistory = [];
let currentAnalysis = null;

// DOM Elements
const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');
const forms = document.querySelectorAll('.analysis-form');
const resultsContainer = document.getElementById('results-container');
const defaultState = document.getElementById('default-state');
const loadingState = document.getElementById('loading-state');
const resultsState = document.getElementById('results-state');
const historyContainer = document.getElementById('history-container');
const historyEmpty = document.getElementById('history-empty');
const historyTable = document.getElementById('history-table');
const historyTbody = document.getElementById('history-tbody');
const toast = document.getElementById('toast');

// Validation functions
const validateTarget = {
  phone: (value) => {
    const cleaned = value.replace(/[^\d+]/g, '');
    return /^[\+]?[1-9][\d]{0,15}$/.test(cleaned);
  },
  
  email: (value) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  },
  
  url: (value) => {
    try {
      new URL(value);
      return true;
    } catch {
      return false;
    }
  }
};

// Format functions
const formatTarget = {
  phone: (value) => {
    const cleaned = value.replace(/[^\d+]/g, '');
    if (cleaned.length === 11 && cleaned.startsWith('1')) {
      return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`;
    }
    return value;
  },
  
  email: (value) => {
    return value.toLowerCase();
  },
  
  url: (value) => {
    if (!/^https?:\/\//i.test(value)) {
      return `https://${value}`;
    }
    return value;
  }
};

// Mock analysis function
function performAnalysis(target, type, options = {}) {
  let threatLevel = "safe";
  let securityScore = 85;
  const details = {};
  const recommendations = [];

  if (type === "email") {
    if (target.includes("suspicious") || target.includes("malware")) {
      threatLevel = "malicious";
      securityScore = 15;
      details.domainReputation = "Poor";
      details.breachStatus = "Found in data breaches";
      recommendations.push("Do not interact with this email");
      recommendations.push("Report as spam/phishing");
    } else if (target.includes("test") || target.includes("temp")) {
      threatLevel = "suspicious";
      securityScore = 45;
      details.domainReputation = "Unknown";
      details.breachStatus = "Not found in known breaches";
      recommendations.push("Exercise caution when interacting");
      recommendations.push("Verify sender identity");
    } else {
      details.domainReputation = "Good";
      details.breachStatus = "Not found in known breaches";
      recommendations.push("Continue monitoring for unusual activity");
      recommendations.push("Enable two-factor authentication if available");
    }
  } else if (type === "url") {
    if (target.includes("malware") || target.includes("phishing") || target.includes("suspicious")) {
      threatLevel = "malicious";
      securityScore = 10;
      details.malwareDetected = true;
      details.phishingRisk = "High";
      details.sslStatus = "Invalid/Missing";
      recommendations.push("Do not visit this website");
      recommendations.push("Block this URL in your security software");
    } else if (!target.startsWith("https://")) {
      threatLevel = "suspicious";
      securityScore = 55;
      details.malwareDetected = false;
      details.phishingRisk = "Medium";
      details.sslStatus = "Not secure (HTTP)";
      recommendations.push("Avoid entering sensitive information");
      recommendations.push("Look for HTTPS version of the site");
    } else {
      details.malwareDetected = false;
      details.phishingRisk = "Low";
      details.sslStatus = "Valid SSL certificate";
      recommendations.push("Website appears safe to visit");
      recommendations.push("Always verify URLs before clicking");
    }
  } else if (type === "phone") {
    if (target.includes("555")) {
      threatLevel = "suspicious";
      securityScore = 40;
      details.carrier = "Unknown";
      details.region = "North America";
      details.spamReports = "Multiple reports";
      recommendations.push("Exercise caution when answering");
      recommendations.push("Do not share personal information");
    } else {
      details.carrier = "Verified carrier";
      details.region = "North America";
      details.spamReports = "No reports found";
      recommendations.push("Number appears legitimate");
      recommendations.push("Monitor for unusual activity");
    }
  }

  return {
    id: generateId(),
    target,
    type,
    threatLevel,
    securityScore,
    details,
    recommendations,
    createdAt: new Date()
  };
}

// Generate unique ID
function generateId() {
  return Math.random().toString(36).substr(2, 9);
}

// Tab switching functionality
function initializeTabs() {
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabId = button.getAttribute('data-tab');
      switchTab(tabId);
    });
  });
}

function switchTab(tabId) {
  // Update tab buttons
  tabButtons.forEach(btn => btn.classList.remove('active'));
  document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');
  
  // Update tab content
  tabContents.forEach(content => content.classList.remove('active'));
  document.getElementById(`${tabId}-content`).classList.add('active');
}

// Form handling
function initializeForms() {
  forms.forEach(form => {
    form.addEventListener('submit', handleFormSubmit);
  });
}

function handleFormSubmit(event) {
  event.preventDefault();
  
  const form = event.target;
  const formData = new FormData(form);
  const type = form.id.replace('-form', '');
  const target = formData.get(`${type}-input`) || document.getElementById(`${type}-input`).value;
  
  // Validate input
  if (!target) {
    showToast(`${type.charAt(0).toUpperCase() + type.slice(1)} is required`);
    return;
  }
  
  if (!validateTarget[type](target)) {
    showToast(`Please enter a valid ${type}`);
    return;
  }
  
  // Get form options
  const options = getFormOptions(type, form);
  
  // Start analysis
  startAnalysis(target, type, options);
}

function getFormOptions(type, form) {
  const options = {};
  
  if (type === 'phone') {
    options.countryCode = document.getElementById('country-select').value;
    options.analysisType = document.getElementById('analysis-type-select').value;
  } else if (type === 'email') {
    options.checkDomainReputation = document.getElementById('domain-reputation').checked;
    options.scanForBreaches = document.getElementById('breach-scan').checked;
  } else if (type === 'url') {
    options.malwareScan = document.getElementById('malware-scan').checked;
    options.phishingDetection = document.getElementById('phishing-detection').checked;
    options.sslCertificateCheck = document.getElementById('ssl-check').checked;
  }
  
  return options;
}

function startAnalysis(target, type, options) {
  // Show loading state
  showLoadingState();
  
  // Simulate API delay
  setTimeout(() => {
    const result = performAnalysis(target, type, options);
    completeAnalysis(result);
  }, 2000);
}

function showLoadingState() {
  defaultState.classList.add('hidden');
  resultsState.classList.add('hidden');
  loadingState.classList.remove('hidden');
}

function completeAnalysis(result) {
  currentAnalysis = result;
  
  // Add to history
  analysisHistory.unshift(result);
  
  // Show results
  showResults(result);
  updateHistory();
  showToast(`Analysis completed for ${result.target}`);
}

function showResults(result) {
  loadingState.classList.add('hidden');
  defaultState.classList.add('hidden');
  resultsState.classList.remove('hidden');
  
  // Update threat level
  updateThreatLevel(result);
  
  // Update security score
  updateSecurityScore(result);
  
  // Update scan details
  updateScanDetails(result);
  
  // Update recommendations
  updateRecommendations(result);
}

function updateThreatLevel(result) {
  const threatBadge = document.getElementById('threat-badge');
  const threatProgressBar = document.getElementById('threat-progress-bar');
  
  threatBadge.className = `threat-badge ${result.threatLevel}`;
  threatBadge.textContent = result.threatLevel;
  
  threatProgressBar.className = `threat-progress-bar ${result.threatLevel}`;
  threatProgressBar.style.width = `${100 - result.securityScore}%`;
}

function updateSecurityScore(result) {
  const securityScore = document.getElementById('security-score');
  const securityDescription = document.getElementById('security-description');
  
  securityScore.textContent = `${result.securityScore}/100`;
  
  if (result.securityScore >= 70) {
    securityScore.className = 'security-score high';
  } else if (result.securityScore >= 40) {
    securityScore.className = 'security-score medium';
  } else {
    securityScore.className = 'security-score low';
  }
  
  let description;
  if (result.threatLevel === "safe") {
    description = "No immediate threats detected. Standard security protocols in place.";
  } else if (result.threatLevel === "suspicious") {
    description = "Some security concerns identified. Exercise caution.";
  } else {
    description = "High-risk threats detected. Immediate action recommended.";
  }
  
  securityDescription.textContent = description;
}

function updateScanDetails(result) {
  const scanStatus = document.getElementById('scan-status');
  const scanDetails = document.getElementById('scan-details');
  
  scanStatus.className = `scan-badge ${result.threatLevel}`;
  
  if (result.threatLevel === "safe") {
    scanStatus.textContent = "✓ Clean";
  } else if (result.threatLevel === "suspicious") {
    scanStatus.textContent = "⚠ Warning";
  } else {
    scanStatus.textContent = "✗ Threat";
  }
  
  // Create details HTML
  let detailsHTML = '';
  Object.entries(result.details).forEach(([key, value]) => {
    const formattedKey = key.replace(/([A-Z])/g, ' $1').trim();
    const formattedValue = typeof value === "boolean" ? (value ? "Yes" : "No") : String(value);
    
    detailsHTML += `
      <div class="detail-item">
        <span>${formattedKey}:</span>
        <span style="font-weight: 500;">${formattedValue}</span>
      </div>
    `;
  });
  
  scanDetails.innerHTML = detailsHTML;
}

function updateRecommendations(result) {
  const recommendationsList = document.getElementById('recommendations-list');
  
  recommendationsList.innerHTML = '';
  result.recommendations.forEach(rec => {
    const li = document.createElement('li');
    li.textContent = rec;
    recommendationsList.appendChild(li);
  });
}

function updateHistory() {
  if (analysisHistory.length === 0) {
    historyEmpty.classList.remove('hidden');
    historyTable.classList.add('hidden');
    return;
  }
  
  historyEmpty.classList.add('hidden');
  historyTable.classList.remove('hidden');
  
  // Clear existing rows
  historyTbody.innerHTML = '';
  
  // Add new rows
  analysisHistory.forEach(item => {
    const row = createHistoryRow(item);
    historyTbody.appendChild(row);
  });
}

function createHistoryRow(item) {
  const row = document.createElement('tr');
  row.setAttribute('data-testid', `history-item-${item.id}`);
  
  // Get type icon
  let typeIcon;
  if (item.type === 'phone') {
    typeIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/>
    </svg>`;
  } else if (item.type === 'email') {
    typeIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
      <polyline points="22,6 12,13 2,6"/>
    </svg>`;
  } else {
    typeIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.72"/>
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.72-1.72"/>
    </svg>`;
  }
  
  row.innerHTML = `
    <td>
      <div class="history-target">
        <div class="icon" style="color: #3b82f6;">${typeIcon}</div>
        <span class="target-text" data-testid="history-target">${item.target}</span>
      </div>
    </td>
    <td>
      <div class="type-badge ${item.type}" data-testid="history-type">${item.type}</div>
    </td>
    <td>
      <div class="threat-badge ${item.threatLevel}" data-testid="history-threat">${item.threatLevel}</div>
    </td>
    <td data-testid="history-date">${formatDate(item.createdAt)}</td>
    <td>
      <button class="view-btn" data-testid="button-view-history" onclick="viewHistoryItem('${item.id}')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      </button>
    </td>
  `;
  
  return row;
}

function formatDate(date) {
  return new Date(date).toLocaleString();
}

function viewHistoryItem(id) {
  const item = analysisHistory.find(h => h.id === id);
  if (item) {
    currentAnalysis = item;
    showResults(item);
    showToast(`Viewing analysis for ${item.target}`);
  }
}

// Toast notification
function showToast(message) {
  const toastMessage = document.getElementById('toast-message');
  toastMessage.textContent = message;
  toast.classList.add('show');
  
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3000);
}

// Action buttons
function initializeActionButtons() {
  // Export button
  document.querySelector('[data-testid="button-export"]').addEventListener('click', () => {
    if (currentAnalysis) {
      exportReport(currentAnalysis);
    } else {
      showToast('No analysis results to export');
    }
  });
  
  // Alert button
  document.querySelector('[data-testid="button-alert"]').addEventListener('click', () => {
    if (currentAnalysis) {
      setAlert(currentAnalysis);
    } else {
      showToast('No analysis results for alert setup');
    }
  });
}

function exportReport(analysis) {
  const report = {
    target: analysis.target,
    type: analysis.type,
    threatLevel: analysis.threatLevel,
    securityScore: analysis.securityScore,
    details: analysis.details,
    recommendations: analysis.recommendations,
    timestamp: analysis.createdAt,
    generatedBy: 'CyberGuard Security Platform'
  };
  
  const dataStr = JSON.stringify(report, null, 2);
  const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
  
  const exportFileDefaultName = `cyberguard-analysis-${analysis.type}-${Date.now()}.json`;
  
  const linkElement = document.createElement('a');
  linkElement.setAttribute('href', dataUri);
  linkElement.setAttribute('download', exportFileDefaultName);
  linkElement.click();
  
  showToast('Report exported successfully');
}

function setAlert(analysis) {
  // Simulate setting up an alert
  showToast(`Alert set for ${analysis.target} monitoring`);
}

// Mobile menu
function initializeMobileMenu() {
  const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
  const navMenu = document.querySelector('.nav-menu');
  
  mobileMenuBtn.addEventListener('click', () => {
    navMenu.style.display = navMenu.style.display === 'flex' ? 'none' : 'flex';
  });
}

// Input validation
function initializeInputValidation() {
  const inputs = document.querySelectorAll('input[type="text"], input[type="email"], input[type="url"]');
  
  inputs.forEach(input => {
    input.addEventListener('blur', validateInput);
    input.addEventListener('input', clearValidationError);
  });
}

function validateInput(event) {
  const input = event.target;
  const value = input.value.trim();
  
  if (!value) return;
  
  const type = input.id.replace('-input', '');
  
  if (validateTarget[type] && !validateTarget[type](value)) {
    input.style.borderColor = '#ef4444';
    showInputError(input, `Please enter a valid ${type}`);
  } else {
    input.style.borderColor = '#3b82f6';
    clearInputError(input);
  }
}

function clearValidationError(event) {
  const input = event.target;
  input.style.borderColor = '#475569';
  clearInputError(input);
}

function showInputError(input, message) {
  clearInputError(input);
  
  const errorDiv = document.createElement('div');
  errorDiv.className = 'input-error';
  errorDiv.style.color = '#ef4444';
  errorDiv.style.fontSize = '0.75rem';
  errorDiv.style.marginTop = '0.25rem';
  errorDiv.textContent = message;
  
  input.parentNode.appendChild(errorDiv);
}

function clearInputError(input) {
  const existingError = input.parentNode.querySelector('.input-error');
  if (existingError) {
    existingError.remove();
  }
}

// Keyboard shortcuts
function initializeKeyboardShortcuts() {
  document.addEventListener('keydown', (event) => {
    // Ctrl/Cmd + Enter to submit form
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      const activeForm = document.querySelector('.tab-content.active .analysis-form');
      if (activeForm) {
        activeForm.dispatchEvent(new Event('submit'));
      }
    }
    
    // Tab switching with numbers
    if (event.key >= '1' && event.key <= '3') {
      const tabIndex = parseInt(event.key) - 1;
      const tabTypes = ['phone', 'email', 'url'];
      if (tabTypes[tabIndex]) {
        switchTab(tabTypes[tabIndex]);
      }
    }
  });
}

// Auto-save form data
function initializeAutoSave() {
  const inputs = document.querySelectorAll('input, select');
  
  inputs.forEach(input => {
    // Load saved value
    const savedValue = localStorage.getItem(`cyberguard_${input.id}`);
    if (savedValue && input.type !== 'checkbox') {
      input.value = savedValue;
    } else if (savedValue && input.type === 'checkbox') {
      input.checked = savedValue === 'true';
    }
    
    // Save on change
    input.addEventListener('change', () => {
      if (input.type === 'checkbox') {
        localStorage.setItem(`cyberguard_${input.id}`, input.checked);
      } else {
        localStorage.setItem(`cyberguard_${input.id}`, input.value);
      }
    });
  });
}

// Progress animation
function animateProgress() {
  const progressFill = document.querySelector('.progress-fill');
  if (progressFill) {
    let width = 0;
    const interval = setInterval(() => {
      width += Math.random() * 10;
      if (width >= 100) {
        width = 100;
        clearInterval(interval);
      }
      progressFill.style.width = `${width}%`;
    }, 200);
  }
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  initializeTabs();
  initializeForms();
  initializeActionButtons();
  initializeMobileMenu();
  initializeInputValidation();
  initializeKeyboardShortcuts();
  initializeAutoSave();
  updateHistory();
  
  // Set default active tab
  switchTab('phone');
  
  console.log('CyberGuard Security Platform initialized');
});

// Service Worker registration for offline support
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then(() => console.log('Service Worker registered'))
      .catch(() => console.log('Service Worker registration failed'));
  });
}

// Analytics tracking (placeholder)
function trackEvent(eventName, eventData) {
  console.log('Analytics Event:', eventName, eventData);
  // In a real application, this would send data to analytics service
}

// Track form submissions
document.addEventListener('submit', (event) => {
  if (event.target.classList.contains('analysis-form')) {
    const formType = event.target.id.replace('-form', '');
    trackEvent('analysis_started', { type: formType });
  }
});

// Performance monitoring
window.addEventListener('load', () => {
  const loadTime = performance.now();
  console.log(`Page loaded in ${loadTime.toFixed(2)}ms`);
  trackEvent('page_load_time', { loadTime });
});
