/* Apply saved theme before page renders */
    (function() {
      if (localStorage.getItem('flux_dark_mode') === '0') document.documentElement.classList.add('light');
    })();
