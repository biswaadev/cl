// FFGlory Panel Shared Helpers
(function() {
    'use strict';
    
    // Dynamically update WhatsApp and Telegram links across the site
    function updateContactLinks() {
        fetch('/api/contact')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (!data) return;
                
                // WhatsApp links
                var waUrl = data.whatsapp_url;
                if (waUrl) {
                    var waLinks = document.querySelectorAll('a[href*="wa.me"], a[href*="whatsapp"], #link-whatsapp, .contact-whatsapp-link');
                    waLinks.forEach(function(el) {
                        el.href = waUrl;
                    });
                }
                
                // Telegram links
                var tgUrl = data.telegram_url;
                if (tgUrl) {
                    var tgLinks = document.querySelectorAll('a[href*="t.me"], #link-telegram, .contact-telegram-link');
                    tgLinks.forEach(function(el) {
                        el.href = tgUrl;
                    });
                }
            })
            .catch(function() { /* silent */ });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', updateContactLinks);
    } else {
        updateContactLinks();
    }

    // Check if free offer or alerts exist
    fetch('/api/client/alerts')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data && data.alerts && data.alerts.length > 0) {
                var offer = data.alerts[0];
                var banner = document.getElementById('tg-offer-banner');
                if (banner && offer.message) {
                    banner.innerHTML = '<div class="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs text-center flex items-center justify-center gap-2">' +
                        '<span>🔥</span> <span>' + offer.message + '</span></div>';
                    banner.classList.remove('hidden');
                }
            }
        })
        .catch(function() { /* silent */ });
})();
