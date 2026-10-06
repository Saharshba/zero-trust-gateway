FROM node:20-alpine AS build
WORKDIR /app

ARG VITE_API_BASE_URL=http://localhost:8000
ARG VITE_GATEWAY_URL=http://localhost:8080
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_GATEWAY_URL=$VITE_GATEWAY_URL

COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
