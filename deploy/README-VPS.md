# Déployer VCyber sur le VPS OVH (n1c0.be)

VCyber tourne comme un petit service Node (`vcyber`, port local **8790**) derrière le Caddy existant.
On n'ajoute que : un utilisateur système, `/opt/vcyber`, une unité systemd `vcyber`, et **un nouveau fichier**
`/etc/caddy/sites/vcyber.caddy`. Rien de ce qui concerne PartyScan (Caddyfile principal, `partyscan-*.caddy`,
Mosquitto, `partyscan-api`, `/srv/sites/partyscan*`, `ps-release`, pare-feu, clés SSH) n'est modifié.
Le pare-feu est déjà bon (ports 22, 80, 443).

## 0. Avant de commencer
1. **Snapshot OVH** dans le manager.
2. Contrôles (sur `ssh nicolas@51.255.45.150`) :
   ```
   free -h ; df -h /
   ss -ltn | grep 8790 || echo "8790 libre"
   node -v          # il faut 20 ou plus
   sudo ls /etc/caddy/sites/
   ```
   Si `node` est absent ou trop ancien : `sudo apt install nodejs npm` (Debian 13 fournit Node 20).

## 1. DNS de n1c0.be
Dans la zone DNS du domaine (là où n1c0.be est géré), créer :
| Type | Nom | Valeur |
|---|---|---|
| A | `@` | 51.255.45.150 |
| A | `www` | 51.255.45.150 |

Ne pas toucher aux éventuels MX / SPF. Si le domaine pointe aujourd'hui vers Netlify ou ailleurs, ces enregistrements le remplacent :
à faire seulement quand le service est prêt (étapes 2 à 5), ou juste avant l'étape 6 (Caddy a besoin du DNS pour obtenir le certificat).

## 2. Utilisateur et code
```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vcyber
sudo git clone https://github.com/N1c-0s/VCyber /opt/vcyber      # ajouter -b <branche> si besoin
sudo chown -R nicolas:nicolas /opt/vcyber
cd /opt/vcyber
npm ci --no-audit --no-fund && npm run build:vps && npm prune --omit=dev --no-audit --no-fund
```

## 3. Service systemd
```
sudo install -m 644 deploy/vcyber.service /etc/systemd/system/vcyber.service
sudo systemctl daemon-reload
sudo systemctl enable --now vcyber
systemctl is-active vcyber
curl -s http://127.0.0.1:8790/healthz        # doit répondre : ok
sudo journalctl -u vcyber -n 20 --no-pager
```

## 4. Caddy (nouveau fichier uniquement, jamais de `restart`)
```
sudo install -m 644 -o root -g root deploy/vcyber.caddy /etc/caddy/sites/vcyber.caddy
sudo caddy validate --config /etc/caddy/Caddyfile
```
**Seulement si la validation réussit :**
```
sudo systemctl reload caddy
```
Si elle échoue : `sudo rm /etc/caddy/sites/vcyber.caddy`, ne rien recharger, et regarder le message.

## 5. Vérifications
```
curl -sI https://n1c0.be | head -5
curl -s https://n1c0.be/api/status | head -c 200
systemctl is-active caddy mosquitto partyscan-api vcyber
```
Puis ouvrir https://n1c0.be (actus, vérification e-mail, outils dont le détecteur de texte IA, cartes) et vérifier que
https://partyscan.app fonctionne toujours (`Net.cred.u` commence par `h-` ou `p-` dans la console).
Au premier démarrage, la page d'actualités peut mettre jusqu'à une minute à se remplir (lecture des flux + traductions, ensuite en cache).

## 6. Mises à jour
```
cd /opt/vcyber && ./deploy/update.sh
```
(`git pull`, build, redémarrage du seul service `vcyber`.)

## 7. Retour arrière
```
sudo systemctl disable --now vcyber
sudo rm /etc/caddy/sites/vcyber.caddy
sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy
```
Ne retire que les éléments de VCyber.

## Différences avec Netlify
- Le cache des traductions est un fichier dans `/var/lib/vcyber/blobs/` (au lieu de Netlify Blobs).
- Le cache de `/api/news` (30 min) et `/api/status` (2 min) et les limites de requêtes (`/api/tools` 30/min, `/api/check` 10/min par IP) sont gérés par le serveur Node.
- La position « de votre IP » vient de ipapi.is (Netlify fournissait sa propre géolocalisation) : la ville peut être un peu différente.
- Les fonctions dans `netlify/functions/` ne sont pas modifiées : le site peut continuer à tourner sur Netlify en parallèle.
