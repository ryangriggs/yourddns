FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

RUN mkdir -p /app/data

EXPOSE 3000

CMD ["node", "--no-warnings=ExperimentalWarning", "src/server.js"]
