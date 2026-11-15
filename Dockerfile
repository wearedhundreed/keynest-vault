FROM node:22-alpine
ENV NODE_ENV=production PORT=4173
WORKDIR /app
COPY package.json server.js index.html app.js styles.css ./
COPY resources ./resources
RUN node --input-type=module -e "import { writeFile } from 'node:fs/promises'; const files = [['password-rules.json', 'password-rules.json'], ['change-password-URLs.json', 'change-password-URLs.json']]; for (const [remote, local] of files) { let ok = false; for (let attempt = 0; attempt < 3 && !ok; attempt++) { try { const response = await fetch('https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/' + remote, { signal: AbortSignal.timeout(20000) }); if (!response.ok) throw Error('HTTP ' + response.status); const text = await response.text(); const parsed = JSON.parse(text); if (!Object.keys(parsed).length) throw Error('Empty dataset'); await writeFile('resources/' + local, text); console.log(local + ': fetched ' + Object.keys(parsed).length + ' Apple records'); ok = true; } catch (error) { console.warn(local + ': upstream attempt ' + (attempt + 1) + ' failed: ' + error.message); } } if (!ok) { const text = await (await import('node:fs/promises')).readFile('resources/' + local, 'utf8'); const parsed = JSON.parse(text); if (!Object.keys(parsed).length) throw Error('No valid fallback for ' + local); console.warn(local + ': using bundled sample fallback'); } }"
USER node
EXPOSE 4173
CMD ["npm", "start"]
