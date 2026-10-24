# VCyber — veille cyber en français

Site de veille cybersécurité hébergé sur Netlify :

- **Actualités** : articles cyber et fuites de données (BleepingComputer, The Hacker News, SecurityWeek, The Record, Krebs, DataBreaches.net, ZATAZ, CERT-FR), traduits en français.
- **Vérifier mon e-mail** : recherche dans les fuites (XposedOrNot, LeakCheck) et test de mot de passe (Pwned Passwords, k-anonymat).
- **Outils** : IP publique et détection VPN/proxy/Tor, DNS, WHOIS (RDAP), en-têtes de sécurité, générateur de mots de passe, état des services.
- **Carte en direct** : carte des cybermenaces Kaspersky.

Structure :
- `public/index.html` : la page
- `netlify/functions/` : fonctions serveur (`news`, `check`, `tools`, `status`)
