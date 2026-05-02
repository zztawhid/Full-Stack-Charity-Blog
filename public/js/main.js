/**
 * Client-side JavaScript
 * 
 * Minimal — most logic is handled server-side for security.
 * This file provides basic UI enhancements only.
 */

// Auto-dismiss alert messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
  const alerts = document.querySelectorAll('.alert-success');
  alerts.forEach(function(alert) {
    setTimeout(function() {
      alert.style.transition = 'opacity 0.5s';
      alert.style.opacity = '0';
      setTimeout(function() {
        alert.remove();
      }, 500);
    }, 5000);
  });
});
